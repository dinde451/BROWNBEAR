# brownbear.js

**Brownbear** is a lightweight, dependency-free cryptography library written in pure JavaScript.  
It's designed to be easily dropped into any project—whether you're running in the browser or Node.js.

## Installation

No build steps. No external packages. Just plug and play.

### In the browser

```html
<script type="module">
  import { sha256, aesGcmEncrypt } from './brownbear.js';
</script>
```
In Node.js

You can either require it directly:

```const { sha256, aesGcmEncrypt } = require('./brownbear.js');```

Or use it as an ES module if your environment supports it:

```import { sha256, aesGcmEncrypt } from './brownbear.js';```

## Usage Example

```
import { sha256, bufferToBase64 } from './brownbear.js';

const message = new TextEncoder().encode('hello world');
const hash = sha256(message);

console.log(bufferToBase64(hash));
// Expected: uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=
```

## Testing

A test.js file is provided to validate each function's correctness.
```node test.js```
