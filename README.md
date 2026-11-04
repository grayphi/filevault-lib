# filevault-lib

A local, serverless key-value object store for efficiently storing files and binary objects on disk, with automatic storage management and no running server required.

## Overview

`filevault-lib` stores binary objects and files in a local vault directory. A vault uses a SQLite catalog (`catalog.db`) to maintain object and file metadata, while the payloads are stored separately:

```text
<container>/
└── <vault-uuid>/
    ├── catalog.db
    ├── files/
    ├── shards/
    └── cache/
```

- `catalog.db` stores the vault catalog and metadata.
- `files/` stores payloads as individual files.
- `shards/` stores multiple payloads in ZIP-based shard files.
- `cache/` is used as an intermediate storage area during some file and stream operations.

The library does not require a separately running database or storage server.

## Installation

Install the package from PyPI:

```bash
pip install filevault-lib
```

## Public API

The package-level API is intended to be imported from `filevault_lib`:

```python
from filevault_lib.vault import Vault
from filevault_lib.utils import (
    CompressAlgo,
    EncryptAlgo,
)
from filevault_lib.querylang import (
    Type,
    Order,
    Query,
    and_,
    or_,
    not_,
    col,
)
```

The sections below document these public classes, enumerations, functions, and the `Vault` interface. The type aliases and supporting definitions from `fvtypes.py` are also described because they define the accepted input and output shapes.

## Quick start

```python
from pathlib import Path

from filevault_lib.vault import Vault

# Create a Vault instance.
vault = Vault(
    key="example",
    container=Path("./vaults"),
)

# Load the vault configuration, create the on-disk structure,
# and open the vault.
vault.load(r"C:\Users\username\path\to\filevault.vaultconf")
vault.create()
vault.open()

# Store a binary object.
key = vault.put(b"Hello from filevault-lib")

# Retrieve it. The payload is returned as an iterator of byte chunks.
result = vault.get(key)
stream, metadata = result[key]

if stream is not None:
    payload = b"".join(stream)
    print(payload)

# Close the vault when finished.
vault.close()
```

`Vault.load()` is required when the instance has not already been given a container. `Vault.create()` creates the directory structure and catalog file. `Vault.open()` initializes the SQLAlchemy engine/session factory and opens the catalog for use.

---

# Vault

`Vault` is the primary interface for creating, opening, storing data in, querying, and maintaining a vault.

## Constructor

```python
Vault(
    key: str,
    container: str | Path = None,
    namespace: str | UUID = None,
) -> None
```

| Parameter | Description |
|---|---|
| `key` | Required vault key/name. An empty value raises `InvalidVaultKey`. |
| `container` | Parent directory in which the vault directory is located. |
| `namespace` | Optional UUID namespace used when deriving the vault UUID. |

The vault UUID is derived from the key and container, using the supplied namespace or the library's configured default namespace. The vault root is the container joined with that UUID.

If `container` is omitted, the instance initially has no resolved container/root. Call `load()` to obtain the container from configuration.

## Vault paths and configuration

The following accessors return the vault's configured paths or configuration object:

| Method | Return value |
|---|---|
| `get_key()` | Vault key |
| `get_container()` | Container path |
| `get_uuid()` | Vault UUID |
| `get_root()` | Vault root directory |
| `get_files_root()` | `<vault-root>/files` |
| `get_shards_root()` | `<vault-root>/shards` |
| `get_cache_root()` | `<vault-root>/cache` |
| `get_catalog()` | `<vault-root>/catalog.db` |
| `get_config()` | `ConfigManager` instance |

Path accessors that depend on a resolved root return `None` when the root has not been resolved.

## Configuration

`filevault` supports an optional configuration file in **TOML format**. It allows users to override the library's built-in `Constants` without modifying the source code.

The configuration filename must end with `.toml` or `.vaultconf`.

### Configuration Structure

Each vault has a unique `key`, which is used to identify the corresponding section in the TOML configuration file. Only the section matching the vault's key is used.

```toml
[my-vault]
MAX_SHARD_SIZE = 1073741824
MAX_FILE_SIZE_IN_SHARD = 20971520
LOOSE_SHARD_SIZE = true
```

Here, `my-vault` represents the vault's key.

All configuration attributes are optional. Users only need to specify the attributes they want to override. Any omitted attribute retains its built-in default value.

### Constants

The following attributes are available for configuration:

| Attribute | Default Value | Description |
|---|---:|---|
| `NAMESPACE` | `"01a0f944-aa5f-72e5-8bc0-25bf1f7d4b78"` | UUID namespace used for generating namespaced identifiers. |
| `MAX_SHARD_SIZE` | `1073741824` (1 GiB) | Maximum target size of a shard. |
| `MAX_FILE_SIZE_IN_SHARD` | `20971520` (20 MiB) | Maximum file size allowed inside a shard. |
| `LOOSE_SHARD_SIZE` | `true` | Allows flexible shard sizing beyond the configured target size. |
| `BULK_OP` | `1024` | Batch size used for bulk operations. |
| `CHUNKS` | `2097152` (2 MiB) | Chunk size used for file processing. |
| `ARGON_MEMORY_KIB` | `8192` | Argon2 memory cost, in KiB. |
| `ARGON_ITERATIONS` | `1` | Argon2 iteration count. |
| `ARGON_LANES` | `1` | Argon2 parallelism parameter. |
| `ENCODING` | `"UTF-8"` | Default text encoding. |
| `SYNC_ON_CLOSE` | `false` | Controls whether data is synchronized when closing. |

Users do not need to define every attribute in their configuration file. The built-in defaults are sufficient for normal operation, and the configuration file is only necessary when customization is required.

### `load()`

```python
load(
    conf_file: Path | str = None,
    conf: ConfigManager = None,
) -> None
```

Loads configuration into the vault instance.

Configuration values are assembled from the library constants, then optionally from a configuration file and a supplied `ConfigManager`. The vault's key and any already-established container, UUID, or namespace are excluded from being overwritten.

After configuration is loaded, the container is resolved, the vault UUID is derived, and the vault root is set.

Use `load()` before `create()` when the constructor was called without a container.

### `save()`

```python
save(to_file: Path | str) -> None
```

Requests that the configuration be saved to `to_file`.

## Create and delete

### `create()`

```python
create() -> None
```

Creates the vault root and the following directories:

- `files/`
- `shards/`
- `cache/`

It also creates `catalog.db` if it does not already exist.

Raises `VaultNotLoadedError` if the vault root has not been resolved.

### `is_created`

```python
vault.is_created  # bool
```

A read-only property. It returns `True` when the vault root and all three storage directories exist as directories, and `catalog.db` exists as a file.

### `delete()`

```python
delete(force: bool = False) -> bool
```

Deletes the vault directory tree.

- The vault must already be created.
- The vault must be closed.
- If `files/`, `shards/`, or `cache/` contains entries, deletion requires `force=True`.
- On successful deletion, the instance's UUID, container, root, and configuration references are cleared.
- Returns a boolean indicating whether deletion occurred.

Raises `VaultNotCreatedError`, `VaultNotClosedError`, or `NonEmptyVaultError` when the corresponding precondition is not met.

## Open and close

### `open()`

```python
open() -> None
```

Opens a created vault.

The method initializes the SQLAlchemy engine and session factory, creates the database schema if needed, and updates the stored vault status to `"open"` when the previous status is missing or `"closed"`.

Calling `open()` on an already-open vault returns without reopening it.

Raises `VaultNotCreatedError` if the vault structure does not exist.

### `is_open`

```python
vault.is_open  # bool
```

A read-only property. It checks whether the instance has an engine and session factory and whether the catalog status is `"open"`.

### `close()`

```python
close() -> None
```

Closes an open vault.

If the `SYNC_ON_CLOSE` configuration option is enabled, `sync()` is called first. The catalog status is then set to `"closed"`, the SQLAlchemy engine is disposed, and the engine/session-factory attributes are removed.

Raises `VaultNotOpenError` if the vault is not open.

## Store data: `put()`

```python
put(
    data: DataInType,
    meta: dict | list[dict] = None,
    encrypt_algo: EncryptAlgoType = EncryptAlgo.NONE,
    encrypt_key: PasskeyType = None,
    compress_algo: CompressAlgoType = CompressAlgo.NONE,
    strict: bool = False,
) -> str | list[str]
```

Stores one or more objects, files, or byte streams and returns the generated key or keys.

### `data`

Accepted input forms are:

- `str`: encoded using the vault's configured `ENCODING`.
- `bytes`: stored as a binary object in the catalog-backed object storage.
- `Path`: treated as a source file. The path must exist, identify a file, and be readable.
- `Iterable[bytes]`: treated as a byte stream.
- `list` of the supported input forms: stores multiple items in one call.

A single input returns a single key. A list input returns a list of keys in input order. A failed item may have a `None` key in the returned list.

### `meta`

Optional metadata associated with each item. It can be one dictionary applied to all items, or a list of dictionaries with one entry per input item.

When a metadata list is supplied, its length must match the input list.

### `encrypt_algo` and `encrypt_key`

Select the encryption algorithm and passphrase.

- `encrypt_algo` accepts an `EncryptAlgo`, its string value, or a list of algorithms for a batch.
- `encrypt_key` accepts a string, bytes, `SecretStr`, or a list of passkeys.
- For a batch, list lengths must match the number of data items.
- A passphrase is required when encryption is enabled.
- `EncryptAlgo.NONE` stores data without encryption.

### `compress_algo`

Selects the compression algorithm. It accepts a `CompressAlgo`, its string value, or a list for batch input. A list must have one entry per input item.

### `strict`

Controls the return behavior after an internal storage/catalog error. With `strict=True`, `put()` returns the keys accumulated so far instead of continuing the remaining work. The implementation logs storage exceptions.

### Examples

Store a binary object:

```python
key = vault.put(b"\x00\x01\x02")
```

Store text with metadata:

```python
key = vault.put(
    "A document",
    meta={"category": "documents", "format": "text"},
)
```

Store a file with compression:

```python
key = vault.put(
    Path("./report.pdf"),
    compress_algo=CompressAlgo.GZIP,
)
```

Store a stream:

```python
def chunks():
    yield b"first "
    yield b"second "
    yield b"third"

key = vault.put(chunks(), meta={"source": "stream"})
```

Store multiple items with per-item settings:

```python
keys = vault.put(
    [b"first object", Path("./image.bin")],
    meta=[
        {"kind": "binary"},
        {"kind": "file"},
    ],
    compress_algo=CompressAlgo.GZIP,
)
```

## Retrieve data: `get()`

```python
get(
    key: str | list[str] | set[str],
    decrypt_key: PasskeyType = None,
) -> DataOutType
```

Retrieves one or more entries by key.

The return value is a dictionary mapping each requested key to a two-item tuple:

```python
{
    "<key>": (
        <iterator of bytes chunks or None>,
        <metadata dictionary or None>,
    )
}
```

The payload is returned as a byte iterator. Consume it to obtain the complete content:

```python
result = vault.get(key)
stream, metadata = result[key]

payload = b"".join(stream) if stream is not None else None
```

For multiple keys, `decrypt_key` can be one passkey shared by all requested keys or a list of passkeys corresponding to the keys. String and byte passkeys are converted to `SecretStr`.

If a key does not exist, the result contains that key with `(None, None)`.

## Remove data: `remove()`

```python
remove(
    keys: str | list[str] | set[str],
    strict: bool = False,
) -> dict[str, bool]
```

Removes the requested keys from the vault.

Returns a dictionary mapping each requested key to a boolean:

- `True`: the entry was successfully removed.
- `False`: the entry was not removed or was not found.

The method handles object records, individual files, and entries stored inside shards. Removing a shard entry marks its shard dirty so that space can be reclaimed during synchronization.

With `strict=True`, the method returns the status accumulated so far when one of its removal stages raises an exception. Errors are logged.

## Statistics: `stats()`

```python
stats() -> dict
```

Returns the statistics supplied by the catalog layer for an open vault.

Raises `VaultNotOpenError` if the vault is not open. The exact dictionary fields are defined by the database/statistics implementation and may depend on the package version.

## Maintenance: `sync()`

```python
sync() -> None
```

Synchronizes the vault's catalog and storage files.

The implementation performs maintenance in these stages:

1. Finds and removes catalog entries that refer to missing individual files (zombie records).
2. Finds and deletes individual files that have no catalog entry (orphan files).
3. Performs the corresponding zombie/orphan checks for files inside shards.
4. Marks affected shards as dirty.
5. Reclaims dirty shard space and marks successfully processed shards clean.

The vault must be created and open. The method logs the start and end of synchronization and warns that the process should not be interrupted.

## Export and import

### `export_vault()`

```python
export_vault(destination: str = "-") -> None
```

Writes a gzip-compressed tar archive containing:

- `config.json`
- `files/`
- `shards/`
- `catalog.db`

When `destination` is `"-"`, the archive is written to standard output. Otherwise, the implementation writes an archive named `fv_export_<timestamp>.vault` in the destination directory (or in the parent directory when the supplied path is not a directory).

### `import_vault()`

```python
@staticmethod
import_vault(
    source: str = "-",
    container: str | Path | None = None,
) -> None
```

Imports an archive created by `export_vault()`.

- `source="-"` reads from standard input; otherwise, `source` is treated as a file path.
- `container` is the target container directory.
- The target directory is created if necessary.
- The archive must begin with `config.json`.
- The imported configuration is updated for the target container and a newly derived vault UUID.
- A configuration file named `fv_conf.vaultconf` is written in the target container.
- Archive members are checked for unexpected paths before extraction.

The current implementation calls `Path(container)`, so a usable `container` must be supplied even though the signature permits `None`.

## Query: `query()`

```python
query(query: Query) -> list[str]
```

Executes a `Query` against the catalog and returns the matching keys as a set of strings.

The vault must be created and open. The argument must be a `Query` instance.

Example:

```python
query = (
    Query()
    .on(Type.DATA)
    .where(col("file_size") >= 1024)
    .order_by((col("file_size"), Order.DESC))
)

keys = vault.query(query)
```


## Shell

```python
shell()
```

Currently raises `NotImplementedError`; it is not an implemented interactive shell.

---

# Compression and encryption algorithms

The algorithm enumerations are defined in `fvtypes.py` and are used by `Vault.put()` and the transformation utilities.

## `CompressAlgo`

```python
class CompressAlgo(str, Enum):
    NONE = "none"
    DEFLATE = "zlib"
    GZIP = "gzip"
    BZIP2 = "bz2"
    XZ = "xz"
    LZMA = "lzma"
```

| Member | Value | Implementation |
|---|---|---|
| `NONE` | `"none"` | No compression |
| `DEFLATE` | `"zlib"` | zlib/DEFLATE stream |
| `GZIP` | `"gzip"` | GZIP-wrapped DEFLATE stream |
| `BZIP2` | `"bz2"` | BZIP2 |
| `XZ` | `"xz"` | XZ/LZMA2 container format |
| `LZMA` | `"lzma"` | LZMA-alone format |

The implementation uses zlib with `MAX_WBITS` for `DEFLATE`, GZIP mode for `GZIP`, BZIP2 for `BZIP2`, XZ format for `XZ`, and LZMA-alone format for `LZMA`.

Example:

```python
key = vault.put(
    Path("./archive.bin"),
    compress_algo=CompressAlgo.XZ,
)
```

## `EncryptAlgo`

```python
class EncryptAlgo(str, Enum):
    NONE = "none"
    AES_GCM = "aes-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"
```

| Member | Value | Implementation |
|---|---|---|
| `NONE` | `"none"` | No encryption |
| `AES_GCM` | `"aes-gcm"` | AES-GCM authenticated encryption |
| `CHACHA20_POLY1305` | `"chacha20-poly1305"` | ChaCha20-Poly1305 authenticated encryption |

For encrypted payloads, the utility implementation derives a 256-bit key from the passphrase using Argon2id. The encrypted representation contains a format header and authenticated records for data chunks, followed by a final authenticated record.

Example:

```python
key = vault.put(
    b"confidential data",
    encrypt_algo=EncryptAlgo.AES_GCM,
    encrypt_key="correct horse battery staple",
)
```

Retrieve it using the same passphrase:

```python
result = vault.get(key, decrypt_key="correct horse battery staple")
payload = b"".join(result[key][0])
```

---

# Query language

The query language provides a small expression API that is compiled to SQLAlchemy expressions and statements. It is used with `Vault.query()`.

Import the query API:

```python
from filevault_lib.querylang import (
    Type,
    Order,
    Query,
    and_,
    or_,
    not_,
    col,
)
```

## `Type`

Selects which catalog records a query examines.

```python
class Type(Enum):
    DATA = "data"
    FILES = "files"
    ANY = "any"
```

| Value | Tables searched |
|---|---|
| `Type.DATA` | Objects table |
| `Type.FILES` | Files and shards tables |
| `Type.ANY` | Objects, files, and shards tables |

`Query()` defaults to `Type.ANY`.

## `Order`

Specifies a sort direction for a query column.

```python
class Order(Enum):
    ASC = "asc"
    DESC = "desc"
```

- `Order.ASC`: ascending.
- `Order.DESC`: descending.

The generated SQL applies `NULLS LAST` to each ordering expression.

## `col()`

```python
col(name: str) -> Column
```

Creates a column reference used to construct query expressions.

```python
col("file_size")
col("name")
col("meta.category")
col("enc_params.argon_iterations")
```

A column name must be a non-empty string.

For ordinary columns, the name must exist on the catalog table being queried. The special prefixes `meta.` and `enc_params.` address nested JSON values. Those JSON expressions are converted to strings by the query compiler.

A column that is not present on one of the tables selected by the query can fail during query compilation. Use fields common to the selected table set, or constrain the query with `Type.DATA` or `Type.FILES` where appropriate.

## Comparison and filter operators

The `Column` object supports the following operators and methods. Each creates an expression; it does not execute a query by itself.

| Expression | Meaning |
|---|---|
| `col("x") < value` | Less than |
| `col("x") > value` | Greater than |
| `col("x") <= value` | Less than or equal |
| `col("x") >= value` | Greater than or equal |
| `col("x") == value` | Equal; `None` is compiled as `IS NULL` |
| `col("x") != value` | Not equal; `None` is compiled as `IS NOT NULL` |
| `col("x").in_(values)` | Value is in a collection |
| `col("x").not_in(values)` | Value is not in a collection |
| `col("x").like(pattern)` | SQL `LIKE` |
| `col("x").ilike(pattern)` | Case-insensitive `LIKE` |
| `col("x").not_like(pattern)` | Negated `LIKE` |
| `col("x").not_ilike(pattern)` | Negated case-insensitive `LIKE` |
| `col("x").between(low, high)` | Inclusive range test |
| `col("x").is_(value)` | SQL `IS` |
| `col("x").is_not(value)` | SQL `IS NOT` |
| `col("x").startswith(value)` | Starts with |
| `col("x").istartswith(value)` | Case-insensitive starts with |
| `col("x").contains(value)` | Contains |
| `col("x").icontains(value)` | Case-insensitive contains |
| `col("x").endswith(value)` | Ends with |
| `col("x").iendswith(value)` | Case-insensitive ends with |

The string matching methods compile to the corresponding SQLAlchemy column operations. Pattern interpretation follows SQLAlchemy/database `LIKE` semantics.

## `and_()`

```python
and_(*expressions: Expr) -> Expr
```

Combines expressions using logical AND.

```python
condition = and_(
    col("file_size") >= 1024,
    col("name").endswith(".pdf"),
)
```

All arguments must be `Expr` instances.

## `or_()`

```python
or_(*expressions: Expr) -> Expr
```

Combines expressions using logical OR.

```python
condition = or_(
    col("name").endswith(".jpg"),
    col("name").endswith(".png"),
)
```

All arguments must be `Expr` instances.

## `not_()`

```python
not_(expression: Expr) -> Expr
```

Negates an expression.

```python
condition = not_(col("meta.status") == "temporary")
```

The argument must be an `Expr` instance.

## `Query`

```python
class Query:
    def __init__(self):
        ...
```

A `Query` is built by chaining `on()`, `where()`, and `order_by()`.

### `on()`

```python
on(target: Type) -> Query
```

Selects the record type (`Type.DATA`, `Type.FILES`, or `Type.ANY`). Returns the same `Query` instance for chaining.

### `where()`

```python
where(condition: Expr) -> Query
```

Sets the filter expression. The argument must be an `Expr`. Returns the same `Query` instance.

Calling `where()` again replaces the previous condition; it does not append another condition automatically. Use `and_()` or `or_()` to combine multiple conditions.

### `order_by()`

```python
order_by(*order: tuple[Column, Order]) -> Query
```

Sets one or more ordering terms. Each term is a `(Column, Order)` pair.

```python
.order_by(
    (col("file_size"), Order.DESC),
    (col("name"), Order.ASC),
)
```

Calling `order_by()` again replaces the previous ordering terms. The generated SQL puts the ordering on the final outer SELECT and uses `NULLS LAST`.

### `to_sqla()`

```python
to_sqla() -> SelectBase
```

Compiles the query to a SQLAlchemy selectable. It is primarily an implementation-level method used by `Vault.query()`.

### Query examples

Find data objects at least 1 KiB in size:

```python
query = (
    Query()
    .on(Type.DATA)
    .where(col("file_size") >= 1024)
)

keys = vault.query(query)
```

Find files with either a PDF or PNG name:

```python
query = (
    Query()
    .on(Type.FILES)
    .where(
        or_(
            col("name").endswith(".pdf"),
            col("name").endswith(".png"),
        )
    )
)

keys = vault.query(query)
```

Combine metadata and size conditions:

```python
query = (
    Query()
    .on(Type.ANY)
    .where(
        and_(
            col("file_size") > 4096,
            col("meta.category") == "images",
            not_(col("meta.status") == "temporary"),
        )
    )
    .order_by((col("file_size"), Order.DESC))
)

keys = vault.query(query)
```

Use a nested metadata field:

```python
query = (
    Query()
    .where(col("meta.owner.team") == "engineering")
)

keys = vault.query(query)
```

---

# Types and supporting definitions

The following definitions are in `fvtypes.py`. They describe internal storage references and the input/output types used by the public methods.

## `KeyringRef`

```python
class KeyringRef(str, Enum):
    UNALLOTED = "U"
    OBJECT = "O"
    FILES = "F"
    SHARDS = "S"
    CACHE = "C"
```

Identifies the storage category used by the storage implementation:

| Member | Value | Meaning |
|---|---|---|
| `UNALLOTED` | `"U"` | Not yet allocated |
| `OBJECT` | `"O"` | Object payload |
| `FILES` | `"F"` | Individual file storage |
| `SHARDS` | `"S"` | Payload stored in a shard |
| `CACHE` | `"C"` | Cache storage |

The member spelling `UNALLOTED` is reproduced from the source.

## `BytesStream`

```python
BytesStream(data: Iterable[bytes])
```

Adapts an iterable of byte chunks to a file-like object with a `read(size=-1)` method.

- `read(size)` returns up to `size` bytes, buffering chunks as needed.
- `read()` or `read(-1)` reads and returns all remaining bytes.
- Once the source iterable is exhausted, subsequent reads return `b""` after the buffer has been consumed.

This adapter is used by the decryption implementation to consume iterable input as a readable stream.

## Input and output type aliases

```python
VaultType: TypeAlias = "ObjectsTable | FilesTable | ShardsTable"

DataInItem: TypeAlias = str | bytes | Path | Iterable[bytes]
DataInType: TypeAlias = DataInItem | list[DataInItem]

DataOutType: TypeAlias = dict[
    str,
    tuple[None | Iterator[bytes], None | dict[str, Any]]
]

PasskeyItem: TypeAlias = str | bytes | SecretStr
PasskeyType: TypeAlias = PasskeyItem | list[PasskeyItem]

CompressAlgoType: TypeAlias = str | CompressAlgo | list[CompressAlgo]
EncryptAlgoType: TypeAlias = str | EncryptAlgo | list[EncryptAlgo]
```

| Alias | Description |
|---|---|
| `VaultType` | One of the ORM table classes used by the query compiler |
| `DataInItem` | One text, bytes, path, or byte-iterable input |
| `DataInType` | One input item or a list of input items |
| `DataOutType` | Mapping of keys to `(byte iterator or None, metadata or None)` |
| `PasskeyItem` | A passphrase represented as `str`, `bytes`, or Pydantic `SecretStr` |
| `PasskeyType` | One passkey or a list of passkeys |
| `CompressAlgoType` | Compression algorithm string, enum, or list of enums |
| `EncryptAlgoType` | Encryption algorithm string, enum, or list of enums |

The aliases describe accepted typing shapes; runtime validation is performed by the relevant methods and utilities.

---

# Storage behavior

## Object, file, and shard storage

The `put()` implementation routes input according to its input type:

- `bytes` inputs are handled as objects in the catalog-backed object path.
- `Path` inputs are processed as files.
- iterable byte inputs are processed as streams.

File and stream payloads are transformed using the selected encryption and compression settings, then placed in individual-file storage or ZIP-based shard storage according to the configured shard/file size limits and storage policy.

The catalog records the key, storage location, metadata, algorithm selections, and encryption parameters needed to retrieve the payload.

## Streaming behavior

The compression, encryption, decryption, and decompression utilities support chunked processing. `Vault.get()` returns byte iterators rather than eagerly joining payload chunks into one `bytes` value.

For callers that want a single in-memory byte string:

```python
stream, metadata = vault.get(key)[key]
payload = b"".join(stream) if stream is not None else None
```

For large payloads, consume the iterator incrementally instead of joining it.

## Encryption passphrases

When encryption is enabled, provide the same passphrase when retrieving the entry. The implementation uses Argon2id to derive the encryption key and AES-GCM or ChaCha20-Poly1305 for authenticated encryption.

Do not store passphrases in source code or commit them to version control. Use an appropriate secret-management mechanism in applications that use encrypted vault entries.

---

# Exceptions

The `Vault` implementation imports and uses the following package exceptions:

| Exception | Usage indicated by implementation |
|---|---|
| `InvalidVaultKey` | Vault key is missing/invalid during construction |
| `InvalidVaultContainer` | A usable container cannot be obtained during configuration loading |
| `VaultNotLoadedError` | An operation such as `create()` is attempted before the vault root is resolved |
| `VaultNotCreatedError` | An operation requires a created vault |
| `VaultNotOpenError` | An operation requires an open vault |
| `VaultNotClosedError` | An operation such as `delete()` requires the vault to be closed |
| `NonEmptyVaultError` | Deletion of a non-empty vault was requested without `force=True` |
| `InputInconsitentException` | Input data, keys, metadata, or per-item option lists are missing, invalid, or inconsistent |

The spelling `InputInconsitentException` is reproduced from the source.

Some lower-level operations may also raise standard Python, SQLAlchemy, compression, archive, or cryptography exceptions. The exact exceptions depend on the operation and input.

---
# License

See the repository's license file for the license terms that apply to `filevault-lib`.
