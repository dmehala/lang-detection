# .NET Core Exe Scanner

This script scan a directory for `.exe` files and inspects the
PE to determine whether they are depending on .NET Core. The 
results is save in a `.csv` file listing all detected .NET Core
applications along with the relevent module find.

## Usage

Install dependencies with `pip install -r requirements.txt`.

```python
python search_dotnet_core_exes.py
```

### Example Output

```python
bin,dotnet_core,module
C:\$GetCurrent\media\sources\setupdiag.exe,True,mscoree.dll
```
