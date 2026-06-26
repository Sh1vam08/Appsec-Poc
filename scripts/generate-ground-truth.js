/**
 * Ground Truth Generator - Phase 1 (ShopSphere Delegate)
 * Delegates execution to generate-ground-truth.py to ensure identical registry output.
 */
const { execSync } = require('child_process');
const path = require('path');

try {
  console.log('Generating Ground Truth Framework (via Python delegate)...');
  const pythonScript = path.join(__dirname, 'generate-ground-truth.py');
  
  let pythonCmd = 'python';
  try {
    execSync('python --version', { stdio: 'ignore' });
  } catch (e) {
    try {
      execSync('python3 --version', { stdio: 'ignore' });
      pythonCmd = 'python3';
    } catch (e2) {
      // Default to python
    }
  }
  
  execSync(`${pythonCmd} "${pythonScript}"`, { stdio: 'inherit' });
} catch (err) {
  console.error('ERROR running Python generator delegate:', err.message);
  process.exit(1);
}
