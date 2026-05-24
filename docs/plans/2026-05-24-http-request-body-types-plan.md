# HTTP Request Body Types Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add high-level HTTP request body helpers for no body, text, raw bytes, multipart form-data, URL encoded forms, and file-backed bodies, excluding JSON/XML-specific handling.

**Architecture:** Keep protocol send paths unchanged. The high-level API owns and builds request body bytes on heap-backed request storage, then continues to expose the final `Body` and `BodyLength` to HTTP/1.1 and HTTP/2. Content-Type is managed by the high-level API so callers do not need to manually compose common body headers.

**Tech Stack:** Windows kernel C++ `/kernel` subset, existing `KhRequest` high-level API, WSK-backed HTTP/HTTPS clients, user-mode C++ regression tests, MSBuild Debug driver build.

---

## File Map

- Modify: `src/KernelHttp/api/KernelHttpApi.h`
  - Add public body-kind enums and descriptor structs.
  - Add high-level request body setter functions.
- Modify: `src/KernelHttp/api/KernelHttpApi.cpp`
  - Add request-owned body storage and release logic.
  - Add heap-only growable body builder helpers.
  - Add URL percent encoding, multipart assembly, and file read helpers.
  - Keep existing `KhHttpRequestSetBody` as raw borrowed body compatibility.
- Modify: `tests/high_level_api_tests.cpp`
  - Add tests for text, raw, urlencode, multipart field, multipart file part, whole-file body, clear body, and validation.
- Create: `tests/testdata/request_body_file.txt`
  - Small deterministic file used by file body tests.

## Task 1: Public API Surface

**Files:**
- Modify: `src/KernelHttp/api/KernelHttpApi.h`

- [ ] **Step 1: Add request body part types**

Add public descriptors:

```cpp
enum class KhRequestBodyPartKind : ULONG
{
    Field = 0,
    FileBytes = 1,
    FilePath = 2
};

struct KhNameValuePair final
{
    const char* Name = nullptr;
    SIZE_T NameLength = 0;
    const char* Value = nullptr;
    SIZE_T ValueLength = 0;
};

struct KhMultipartFormDataPart final
{
    KhRequestBodyPartKind Kind = KhRequestBodyPartKind::Field;
    const char* Name = nullptr;
    SIZE_T NameLength = 0;
    const char* Value = nullptr;
    SIZE_T ValueLength = 0;
    const UCHAR* Data = nullptr;
    SIZE_T DataLength = 0;
    const char* FilePath = nullptr;
    SIZE_T FilePathLength = 0;
    const char* FileName = nullptr;
    SIZE_T FileNameLength = 0;
    const char* ContentType = nullptr;
    SIZE_T ContentTypeLength = 0;
};
```

- [ ] **Step 2: Add body setter declarations**

Add:

```cpp
NTSTATUS KhHttpRequestClearBody(_In_ KH_REQUEST request) noexcept;
NTSTATUS KhHttpRequestSetTextBody(...);
NTSTATUS KhHttpRequestSetRawBody(...);
NTSTATUS KhHttpRequestSetUrlEncodedBody(...);
NTSTATUS KhHttpRequestSetMultipartFormDataBody(...);
NTSTATUS KhHttpRequestSetFileBody(...);
```

Keep raw bytes possible through both existing `KhHttpRequestSetBody` and new owned raw body helper.

## Task 2: Owned Body Storage and Header Management

**Files:**
- Modify: `src/KernelHttp/api/KernelHttpApi.cpp`

- [ ] **Step 1: Extend `KhRequest`**

Add owned body fields:

```cpp
UCHAR* OwnedBody = nullptr;
SIZE_T OwnedBodyLength = 0;
SIZE_T OwnedBodyCapacity = 0;
```

- [ ] **Step 2: Release owned body**

Update `ReleaseRequestStorage` and body reset helpers to zero and free owned body memory.

- [ ] **Step 3: Add Content-Type replacement helper**

Implement a helper that removes existing `Content-Type` headers before adding a new one. It must free removed header storage and compact the header array.

## Task 3: Heap-Backed Body Builder

**Files:**
- Modify: `src/KernelHttp/api/KernelHttpApi.cpp`

- [ ] **Step 1: Implement growable append helpers**

Implement request-owned capacity growth using `AllocateApiMemory` and `FreeApiMemory`, doubling capacity until the required size fits. Do not use stack arrays for request body bytes.

- [ ] **Step 2: Implement text and raw setters**

Text copies bytes and defaults Content-Type to `text/plain; charset=utf-8` unless a caller supplies a content type. Raw copies bytes and only sets Content-Type when supplied.

- [ ] **Step 3: Implement URL encoded body**

Validate key/value pairs, percent-encode names and values, join with `&`, and set Content-Type to `application/x-www-form-urlencoded`.

- [ ] **Step 4: Implement multipart form-data**

Generate a deterministic boundary from the request pointer and body length counter, assemble each part, support field bytes, file bytes, and file path parts, and set Content-Type to `multipart/form-data; boundary=<boundary>`.

- [ ] **Step 5: Implement file body**

Read a file path at PASSIVE_LEVEL into request-owned heap storage and default Content-Type to `application/octet-stream` unless a caller supplies one.

## Task 4: Regression Tests

**Files:**
- Modify: `tests/high_level_api_tests.cpp`
- Create: `tests/testdata/request_body_file.txt`

- [ ] **Step 1: Add transport assertions**

Use the existing test transport to capture built requests and assert bodies and headers.

- [ ] **Step 2: Cover all requested body types**

Add tests for:
- Clear/no body.
- Text body.
- Raw body.
- URL encoded fields.
- Multipart form-data field.
- Multipart file bytes.
- Multipart file path.
- Whole-file body.

- [ ] **Step 3: Cover validation**

Reject null non-empty data, invalid pair arrays, invalid multipart parts, and missing file paths.

## Task 5: Verification

**Files:**
- Existing build/test files.

- [ ] **Step 1: Run high-level API tests**

Run the existing high-level API test binary or compile/run it using the established test command.

- [ ] **Step 2: Run broader relevant tests**

Run non-smoke unit tests that cover HTTP parsing/request construction and high-level API behavior.

- [ ] **Step 3: Run Debug build**

Run:

```powershell
msbuild KernelHttp.sln /p:Configuration=Debug /p:Platform=x64
```

Do not add a timeout wait around Debug or Release package/build commands.
