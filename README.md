# GhiDump 2.0

## Introduction
**GhiDump 2.0** is a modern Ghidra plugin that automatically exports binary analysis results to Redis using MessagePack serialization. It features a normalized data model that eliminates redundancy and provides efficient data transfer for downstream processing.

The plugin automatically triggers when Ghidra completes analysis of a binary, making it ideal for automated reverse engineering pipelines and code intelligence platforms.

## Key Features

- **Automatic Export**: Triggers automatically when analysis completes
- **Normalized Data Model**: No string duplication, efficient storage
- **MessagePack Serialization**: Compact binary format, faster than Protocol Buffers
- **Redis Pub/Sub**: Decoupled architecture for scalable processing
- **Console Logging**: Detailed debug and info output for monitoring
- **Configurable**: Redis connection settings via Ghidra options

## Installation

1. Set your Ghidra installation directory:
   ```bash
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```

2. Build the extension:
   ```bash
   gradle
   ```

3. Install in Ghidra:
   - Open Ghidra
   - `File > Install Extensions... > Add extension`
   - Select the generated `dist/ghidra_*_Ghidump.zip`
   - Restart Ghidra

## Usage

### Automatic Mode
Once installed, GhiDump 2.0 automatically exports analysis results when Ghidra completes analyzing a binary. No manual intervention required!

### Configuration
Configure the plugin via Ghidra's options:
- `Edit > Tool Options > Ghidump`
  - **Redis Host**: Redis server hostname (default: localhost)
  - **Redis Port**: Redis server port (default: 6379)
  - **Enabled**: Toggle automatic export (default: true)

### Redis Setup
Run Redis with RediSearch module:
```bash
docker run -d --name redis-stack -p 6379:6379 -p 8001:8001 redis/redis-stack:latest
```

## Architecture

### Data Model
The plugin uses a normalized data model with three main components:

```java
AnalysisResult
├── binaryName: String
├── binaryMd5: String
├── stringTable: List<String>  // All unique strings
├── functions: Map<Integer, FunctionObject>
└── basicBlocks: Map<Integer, BasicBlockObject>
```

- **String Table**: All strings are stored once and referenced by index
- **Functions**: Contain name ID (index into string table) and list of basic block IDs
- **Basic Blocks**: Contain disassembled code for embedding generation

### Data Flow
1. Ghidra analyzes binary
2. Analysis completion triggers GhidumpPlugin
3. Plugin builds normalized data model
4. Serializes to MessagePack
5. Publishes to Redis channel `ghidump:tasks`
6. Python workers (separate project) consume and process data

## Console Output

The plugin provides detailed console output:
```
[Ghidump 2.0] Analysis completed for: example.exe
[Ghidump 2.0] Building normalized data model...
[Ghidump 2.0] Model built: 523 functions, 2341 basic blocks, 892 unique strings
[Ghidump 2.0] Serializing to MessagePack...
[Ghidump 2.0] Serialized to 45632 bytes (44.56 KB)
[Ghidump 2.0] Publishing to Redis at localhost:6379...
[Ghidump 2.0] Successfully published to Redis channel 'ghidump:tasks'
```

## Development

### Project Structure
```
src/main/java/ghidump/
├── GhidumpPlugin.java         # Main plugin class
├── DataModeler.java           # Builds normalized model
├── model/                     # Data model (Java Records)
│   ├── AnalysisResult.java
│   ├── FunctionObject.java
│   └── BasicBlockObject.java
├── serialization/
│   └── MessagePackSerializer.java
└── communication/
    └── RedisPublisher.java
```

### Building from Source
```bash
# Clone the repository
git clone https://github.com/r0metheus/GhiDump.git
cd GhiDump

# Set Ghidra directory
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# Build
gradle

# The extension will be in dist/
```

## Python Intelligence Platform

A separate Python project (coming soon) will provide:
- Redis subscriber to consume exported data
- Vector embedding generation using sentence-transformers
- Semantic search API using FastAPI
- RediSearch integration for similarity queries

## License
[GPLv3](https://github.com/r0metheus/GhiDump/blob/master/LICENSE)