---
slug: file-upload-validation
name: Insufficient File Upload Validation
description: 'File upload handlers (multer, formidable, busboy, Flask, Django, Multer-style middleware) that accept any size, extension, or MIME type — leads to RCE via uploaded scripts, storage exhaustion, double-extension bypass, or XSS via stored HTML/SVG.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: 'multer|busboy|formidable|MultipartFile|move_uploaded_file|\$_FILES|request\.files|request\.FILES|CarrierWave|shrine|paperclip'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs,py,rb,go,php,java,kt,cs}'
        label: file upload library or pattern
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - py
    - rb
    - go
    - php
    - java
    - kt
    - cs
  preFilter:
    - regex: 'multer|busboy|formidable|express-fileupload|multiparty|@fastify/multipart'
      label: Node.js upload middleware
    - regex: 'req\.(file|files)\b'
      label: Express/multer req.file result
    - regex: 'request\.(files|FILES)\[|\bFileStorage\b|\bUploadedFile\b'
      label: Python Flask/Django upload
    - regex: 'MultipartFile|MultipartHttpServletRequest|@RequestPart|CommonsMultipartFile|ServletFileUpload|DiskFileItemFactory|\bFileItem\b'
      label: Java/Kotlin multipart
    - regex: 'request\.getPart\(|request\.getParts\('
      label: Java Servlet Part API
    - regex: '\$_FILES|move_uploaded_file|is_uploaded_file'
      label: PHP file upload
    - regex: 'CarrierWave|shrine|paperclip|ActionDispatch::Http::UploadedFile|original_filename'
      label: Ruby upload library
    - regex: 'r\.FormFile\(|ParseMultipartForm|multipart\.FileHeader'
      label: Go multipart upload
    - regex: '\bIFormFile\b|HttpPostedFileBase|Request\.Files\b|MultipartFormDataContent'
      label: C# file upload
references:
  - CWE-434
  - CWE-400
  - 'OWASP-A04:2021'
---

You are reviewing source code for insufficient file upload validation —
endpoints that accept user-uploaded files but do not enforce a size
limit, extension/MIME allowlist, or content-type sanity check before
storing or processing the file.

The risk depends on what happens with the file:
- Stored under the web root → uploaded `.php`/`.jsp` becomes RCE.
- Stored as static assets → uploaded HTML/SVG becomes stored XSS.
- Parsed (XML/YAML/ZIP/image) → triggers downstream parser bugs (XXE,
  zip slip, image-library RCE).
- No size limit → DoS via disk fill or memory exhaustion.

## What to look for

**Node.js — multer:**
```ts
const upload = multer({ dest: "uploads/" });           // no limits, no fileFilter
app.post("/u", upload.single("file"), handler);
```
The unsafe defaults: no `limits.fileSize`, no `limits.files`, no
`fileFilter`.

**Node.js — formidable / busboy / express-fileupload:**
```ts
const form = formidable({ multiples: true });          // no maxFileSize, no filter
form.parse(req, ...);

const bb = busboy({ headers: req.headers });           // no limits
```

**Python — Flask / Werkzeug:**
```python
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    f.save(os.path.join(UPLOAD_DIR, f.filename))       # untrusted filename, no checks
```
No `MAX_CONTENT_LENGTH` set, no extension allowlist, `f.filename` saved
verbatim (combine with path traversal).

**Django:**
```python
def upload(request):
    f = request.FILES["file"]
    with open(f"/media/{f.name}", "wb") as out:
        for chunk in f.chunks():
            out.write(chunk)
```

**Ruby on Rails — CarrierWave / Active Storage:** Missing
`content_type_allowlist`, `size_range`, or `extension_allowlist` on the
uploader class.

**PHP:**
```php
move_uploaded_file($_FILES["file"]["tmp_name"], "/uploads/" . $_FILES["file"]["name"]);
```
No `getimagesize`/MIME check, no extension validation, filename
attacker-controlled.

**Java — Spring MultipartFile:**
```java
@PostMapping("/u")
public String upload(@RequestParam MultipartFile file) {
    file.transferTo(new File("/uploads/" + file.getOriginalFilename()));
    return "ok";
}
```

**Validation patterns that, if PRESENT, mean the handler is protected:**
- `limits: { fileSize: ... }`, `maxFileSize`, `MAX_CONTENT_LENGTH`.
- `fileFilter` / `accept` / `content_type_allowlist` / a MIME or
  extension allowlist.
- Use of `path.basename(file.originalname)` (defangs path traversal).
- Magic-number check via `file-type` / `python-magic` / `Tika`.
- Storage under an opaque path (UUID filename, not the original).

## True positive criteria

Flag when a handler accepts an uploaded file AND has none of the
following:

1. A size limit (per-file or per-request).
2. An extension or MIME allowlist (or magic-number check).
3. Storage path that ignores the original filename (UUID/random name)
   — without this, both path traversal and double-extension attacks
   remain open.

A single missing check is a finding if the file is then **executed,
served, or parsed** — that's where the impact lands.

## What to ignore

- Handlers that only accept uploads from internal/admin users with a
  separate authz check, and the missing limit is documented.
- Test fixtures.
- Upload handlers that write to an opaque blob store (S3 with random
  keys, no public read) AND have a downstream worker that re-validates
  before serving.
- Code paths where the file is hashed and discarded (e.g., virus-scan
  inputs that aren't kept).

## Examples

True positives:
```ts
// multer with defaults — no size limit, no filter, original filename
const upload = multer({ dest: "public/uploads/" });
app.post("/avatar", upload.single("file"), (req, res) => {
  res.json({ url: `/uploads/${req.file.originalname}` });
});
```
```python
# Flask — saves attacker-controlled filename to disk, no checks
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    f.save(f"/var/www/uploads/{f.filename}")
    return "ok"
```

False positives to skip:
```ts
// multer with explicit limits + MIME filter + opaque storage
const upload = multer({
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    cb(null, ["image/png", "image/jpeg"].includes(file.mimetype));
  },
  storage: multer.diskStorage({
    destination: "uploads/",
    filename: (req, file, cb) => cb(null, randomUUID() + path.extname(file.originalname)),
  }),
});
```
```python
# Django UploadedFile with explicit validators on a Form
class UploadForm(forms.Form):
    file = forms.FileField(
        validators=[FileExtensionValidator(["png", "jpg"]), MaxValueValidator(5_000_000)]
    )
```

If the file is stored but never served or executed (e.g., immediately
sent to S3, scanned, and deleted), the impact is lower — note the
finding but reduce severity.
