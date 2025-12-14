# Secure Input Handling Assignment

**Author:** Paul Sommers  
**Course:** SDEV245 - Secure Software Development  
**GitHub:** https://github.com/psommers1/Module-7-Assignment-Secure-Input-Handling

## Overview

This assignment focuses on identifying and fixing security vulnerabilities related to variable declarations, type safety, input validation, and regular expression patterns. The solutions demonstrate secure coding practices for preventing type mismatches, integer overflows, and improper input validation.

---

# Part A: Variable Security Issues

## Exercise 1: Undeclared Variable (Java)

### Insecure Code

```java
public class Exercise1 {

  public static void main(String[] args) {

      z = 24;
      System.out.println("The value of z is: " + z);
  }
}
```

### Identification of Issue

The variable `z` is used without being declared with a data type.

### Security Risk

In Java, all variables must be explicitly declared with a type before use. This code will not compile, preventing execution. While compilation errors prevent runtime exploitation, the lack of type declaration demonstrates poor coding practices that can lead to:
- Type confusion vulnerabilities if the code were modified to compile
- Undefined behavior in weakly-typed languages
- Potential integer overflow if the wrong type is inferred
- Reduced code maintainability and security review difficulty

### Corrected Code

```java
public class Exercise1 {

  public static void main(String[] args) {

      // Explicitly declare the variable with appropriate type
      int z = 24;
      System.out.println("The value of z is: " + z);
  }
}
```

### Explanation of Fix

The fix explicitly declares `z` as an `int` data type before assignment. This:
- Ensures type safety and prevents type confusion
- Makes the code compile and run correctly
- Clearly defines the variable's intended use and range
- Allows the compiler to perform type checking and catch potential errors
- Follows Java's strong typing requirements for security

---

## Exercise 2: Type Mismatch (Java)

### Insecure Code

```java
public class Exercise2 {

    public static void main(String[] args) {

      String y = 10;
      System.out.println("The value of y is: " + y);
  }
}
```

### Identification of Issue

The variable `y` is declared as a `String` type but assigned an integer value `10`.

### Security Risk

This code contains a type mismatch that violates Java's type safety. While this won't compile in Java, the security risks of type mismatches include:
- Type confusion leading to unexpected behavior
- Potential buffer overflows if implicit conversions occur
- Logic errors when the variable is used in operations expecting a specific type
- Bypass of input validation if type coercion occurs
- In languages with weaker type systems, this could allow attackers to exploit type juggling vulnerabilities

### Corrected Code

```java
public class Exercise2 {

    public static void main(String[] args) {

      // Option 1: Use int type for numeric value
      int y = 10;
      System.out.println("The value of y is: " + y);
      
      // Option 2: Use String type with proper string literal
      // String y = "10";
      // System.out.println("The value of y is: " + y);
  }
}
```

### Explanation of Fix

The fix provides two options:
1. **Option 1 (recommended):** Declare `y` as `int` to match the numeric value being assigned. This allows proper mathematical operations and type checking.
2. **Option 2:** Keep `y` as `String` but use a string literal `"10"` instead of the numeric value.

The corrected code:
- Maintains type consistency between declaration and assignment
- Enables the compiler to enforce type safety
- Prevents type confusion vulnerabilities
- Makes the code's intent clear and maintainable
- Follows Java's strong typing model for security

---

## Exercise 3: Missing Input Validation (Python)

### Insecure Code

```python
# Output the sum of an array's values
items = [10, 20, 30, 40, 50]

def sum_array(arr):
    total = 0

    for i in range(len(arr)):
        total += arr[i]
    return total

result = sum_array(items)

print("Sum of elements in the array:", result)
```

### Identification of Issue

While this code functions correctly for the given input, it lacks input validation and bounds checking. The function assumes `arr` is always a valid list of numbers.

### Security Risk

The code has several security vulnerabilities:
- **No type validation:** Function accepts any parameter type, could receive non-list types causing runtime errors
- **No element validation:** Assumes all array elements are numeric; non-numeric elements cause TypeError
- **No bounds checking:** While Python handles this automatically, the pattern of accessing by index without validation is risky
- **Integer overflow potential:** In Python 2 or when dealing with large numbers, accumulation could cause issues
- **Denial of Service:** Extremely large arrays could consume excessive memory/CPU
- **Code injection risk:** If array elements come from user input without validation, malicious data could be processed

### Corrected Code

```python
# Output the sum of an array's values with input validation
items = [10, 20, 30, 40, 50]

def sum_array(arr):
    # Validate input is a list
    if not isinstance(arr, list):
        raise TypeError("Input must be a list")
    
    # Validate list is not empty
    if len(arr) == 0:
        return 0
    
    # Validate list size to prevent DoS
    if len(arr) > 10000:
        raise ValueError("Array too large - maximum 10,000 elements allowed")
    
    total = 0
    
    # Validate each element is numeric
    for i in range(len(arr)):
        if not isinstance(arr[i], (int, float)):
            raise TypeError(f"Element at index {i} must be numeric, got {type(arr[i]).__name__}")
        
        # Additional check for safe numeric range
        if abs(arr[i]) > 1e15:
            raise ValueError(f"Element at index {i} exceeds safe numeric range")
        
        total += arr[i]
    
    return total

# Safe execution with error handling
try:
    result = sum_array(items)
    print("Sum of elements in the array:", result)
except (TypeError, ValueError) as e:
    print(f"Error: {e}")
```

### Explanation of Fix

The corrected code implements comprehensive input validation:

1. **Type validation:** Ensures input is a list type before processing
2. **Empty list handling:** Returns 0 for empty lists instead of potentially undefined behavior
3. **Size limit:** Prevents denial-of-service attacks from extremely large arrays (configurable limit of 10,000 elements)
4. **Element type checking:** Validates each element is numeric (int or float) before arithmetic operations
5. **Range validation:** Checks for excessively large numbers that could cause numeric issues
6. **Error handling:** Uses exceptions to handle invalid input gracefully
7. **Descriptive errors:** Provides clear error messages for debugging and security logging

These protections prevent:
- Type confusion attacks
- Denial of service from resource exhaustion
- Runtime errors from invalid data
- Integer overflow issues
- Processing of malicious input data

---

## Exercise 4: Invalid Syntax and Logic Error (Python)

### Insecure Code

```python
# Simple Python program to calculate the sum of a set of numbers supplied by the user

integer total = 1
integer num_count = 1
float num = 1

num_count = int(input("How many numbers do you want to add? "))

for i in range(num_count):
    num = float(input("Enter number {}: ".format(i+1)))
    
    total += num

print("The sum of the numbers you entered is:", total)
```

### Identification of Issue

Multiple security and correctness issues exist:
1. Python does not support type declarations like `integer` or `float` before variable names
2. `total` is initialized to `1` instead of `0`, causing incorrect sum calculation
3. No input validation on user-supplied values
4. No bounds checking on `num_count`

### Security Risk

This code has critical security vulnerabilities:

- **Syntax errors:** Code will not run due to invalid Python syntax (`integer total = 1`)
- **Logic error:** Starting `total` at 1 instead of 0 causes incorrect calculations, potential financial/scientific errors
- **No input validation:** Malicious users can:
  - Enter negative numbers for `num_count` causing no iterations
  - Enter extremely large values causing denial-of-service
  - Enter non-numeric strings causing crashes
  - Cause integer overflow with extremely large numbers
- **Resource exhaustion:** No limit on loop iterations allows DoS attacks
- **Type confusion:** Mixing int and float without validation can cause precision issues
- **No error handling:** Crashes expose system information in stack traces

### Corrected Code

```python
# Secure Python program to calculate the sum of numbers supplied by the user

# Initialize variables with correct syntax and values
total = 0  # Start at 0 for correct sum calculation
num_count = 0
num = 0.0

# Input validation for number count
while True:
    try:
        num_count = int(input("How many numbers do you want to add? "))
        
        # Validate range - prevent DoS and negative values
        if num_count < 0:
            print("Error: Number count cannot be negative. Please try again.")
            continue
        if num_count > 100:
            print("Error: Maximum 100 numbers allowed. Please try again.")
            continue
        
        break  # Valid input received
    except ValueError:
        print("Error: Please enter a valid integer.")

# Collect and sum numbers with validation
for i in range(num_count):
    while True:
        try:
            num = float(input("Enter number {}: ".format(i+1)))
            
            # Validate numeric range to prevent overflow
            if abs(num) > 1e15:
                print("Error: Number too large. Please enter a smaller value.")
                continue
            
            total += num
            break  # Valid input received
        except ValueError:
            print("Error: Please enter a valid number.")

print("The sum of the numbers you entered is:", total)
```

### Explanation of Fix

The corrected code implements multiple security improvements:

1. **Correct Python syntax:** Removes invalid type declarations (`integer`, `float` keywords)
2. **Correct initialization:** Sets `total = 0` for accurate sum calculation
3. **Input validation loop:** Uses try-except blocks to catch invalid input gracefully
4. **Range validation:** 
   - Prevents negative `num_count` values
   - Limits maximum count to 100 to prevent DoS attacks
   - Validates numbers are within safe range (±1e15)
5. **Type safety:** Converts user input to appropriate types with error handling
6. **Error messages:** Provides clear feedback without exposing system details
7. **Retry mechanism:** Allows users to correct invalid input instead of crashing
8. **Resource limits:** Prevents resource exhaustion from excessive iterations

These fixes prevent:
- Calculation errors from incorrect initialization
- Denial-of-service attacks from large inputs
- System crashes from invalid data types
- Integer/float overflow vulnerabilities
- Information disclosure from error messages

---

## Exercise 5: Integer Overflow (C#)

### Insecure Code

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        int number = int.MaxValue;
        number += 1;
        Console.WriteLine("The incremented value is: " + number);
    }
}
```

### Identification of Issue

The code increments an integer variable that is already at its maximum value (`int.MaxValue`), causing integer overflow.

### Security Risk

Integer overflow is a critical security vulnerability:

- **Silent wraparound:** In C# (unchecked context), `int.MaxValue + 1` wraps to `int.MinValue` (-2,147,483,648) without error
- **Logic bypasses:** Overflow can bypass security checks (e.g., buffer size validation, loop conditions)
- **Buffer overflows:** Overflow in buffer size calculations can allocate insufficient memory
- **Authentication bypass:** In some contexts, negative values from overflow can bypass authentication
- **Financial errors:** In financial calculations, overflow causes severe data corruption
- **Array index vulnerabilities:** Overflow in array indexing can access out-of-bounds memory
- **Denial of service:** Unexpected negative values can crash systems
- **Privilege escalation:** Overflow in user ID or permission calculations can grant unauthorized access

CVE Examples:
- CVE-2021-3156 (Sudo vulnerability): Integer overflow led to heap-based buffer overflow
- Many historical vulnerabilities in iOS, Android, and Windows kernel

### Corrected Code

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        // Solution 1: Use checked arithmetic to detect overflow
        try
        {
            checked
            {
                int number = int.MaxValue;
                number += 1;  // This will throw OverflowException
                Console.WriteLine("The incremented value is: " + number);
            }
        }
        catch (OverflowException)
        {
            Console.WriteLine("Error: Integer overflow detected. Operation cancelled.");
        }
        
        // Solution 2: Use larger data type to accommodate the value
        long numberLong = int.MaxValue;
        numberLong += 1;
        Console.WriteLine("The incremented value is: " + numberLong);
        
        // Solution 3: Validate before operation
        int numberValidated = int.MaxValue;
        if (numberValidated < int.MaxValue)  // Check if increment is safe
        {
            numberValidated += 1;
            Console.WriteLine("The incremented value is: " + numberValidated);
        }
        else
        {
            Console.WriteLine("Error: Cannot increment - value is at maximum.");
        }
    }
}
```

### Explanation of Fix

The corrected code provides three approaches to prevent integer overflow:

**Solution 1: Checked Arithmetic (Recommended for critical operations)**
- Uses C# `checked` keyword to enable overflow checking
- Throws `OverflowException` when overflow occurs instead of silent wraparound
- Allows graceful error handling and security logging
- Prevents exploitation of overflow vulnerabilities

**Solution 2: Larger Data Type**
- Uses `long` (64-bit) instead of `int` (32-bit) for larger value range
- Provides room for growth without overflow
- Appropriate when values may exceed 32-bit range
- Still requires bounds checking for extremely large values

**Solution 3: Pre-validation**
- Checks if the operation would cause overflow before performing it
- Prevents the overflow from occurring
- Most performant option (no exception handling)
- Suitable when overflow conditions are predictable

**Best Practices Implemented:**
- Always validate arithmetic operations on untrusted input
- Use checked arithmetic for security-critical calculations
- Choose appropriate data types for expected value ranges
- Handle overflow conditions explicitly rather than allowing wraparound
- Log overflow attempts for security monitoring
- Never rely on silent integer wraparound behavior

These protections prevent:
- Buffer overflow vulnerabilities
- Authentication and authorization bypasses
- Financial calculation errors
- Array bounds violations
- Denial-of-service conditions
- Privilege escalation attacks

---

# Part B: Regular Expression Validation Issues

## Exercise 1: URL Regex - Incomplete Pattern Matching

### Insecure Code

```java
import java.util.regex.*;

public class URLExtractor {
    public static void main(String[] args) {
        String text = "Visit my website at http://www.url example.com";
        String regex = "https?://.+";

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(text);

        while (matcher.find()) {
            System.out.println("URL: " + matcher.group());
        }
    }
}
```

### Identification of Regex Issue

The current regex pattern is: `https?://.+`

The suggested comparison pattern is: `https?://\\S+`

### Security Risk and Difference Explanation

**Difference between `.+` and `\\S+`:**

- **`.+` (current pattern):** Matches one or more of ANY character (including spaces, tabs, newlines)
- **`\\S+` (better pattern):** Matches one or more NON-WHITESPACE characters

**Security risks of using `.+`:**

1. **Overly greedy matching:** The `.+` pattern will match across spaces and capture text beyond the actual URL
   - In the example, it captures: `http://www.url example.com` (includes space and text after space)
   - This is not a valid URL format

2. **ReDoS (Regular Expression Denial of Service):** The `.+` with greedy matching can cause catastrophic backtracking on malicious input

3. **Data leakage:** May capture sensitive data that appears after URLs in logs or text

4. **Validation bypass:** Accepts malformed URLs with spaces, allowing injection of malicious content

5. **Log injection:** Spaces in URLs could be used to inject fake log entries

### Corrected Code

```java
import java.util.regex.*;

public class URLExtractor {
    public static void main(String[] args) {
        String text = "Visit my website at http://www.url example.com";
        
        // Corrected regex using \\S+ instead of .+
        String regex = "https?://\\S+";

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(text);

        while (matcher.find()) {
            System.out.println("URL: " + matcher.group());
        }
        
        // Even better: More comprehensive URL validation
        // This pattern validates proper URL structure
        String betterRegex = "https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/[^\\s]*)?";
        Pattern betterPattern = Pattern.compile(betterRegex);
        Matcher betterMatcher = betterPattern.matcher(text);
        
        System.out.println("\nWith improved validation:");
        while (betterMatcher.find()) {
            System.out.println("Valid URL: " + betterMatcher.group());
        }
    }
}
```

### Explanation of Fix

The corrected code implements two levels of improvement:

**Basic Fix: `https?://\\S+`**
- `\\S+` matches one or more non-whitespace characters
- Stops at spaces, preventing over-capture
- Does not match across line breaks
- More performant than `.+`
- Prevents basic injection and data leakage

**Enhanced Fix: `https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/[^\\s]*)?`**
- Validates protocol: `https?://`
- Validates domain: `[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}` (requires valid domain format)
- Validates path: `(/[^\\s]*)?` (optional path without whitespace)
- Rejects malformed URLs with spaces
- More resistant to injection attacks
- Provides proper URL structure validation

**Security improvements:**
- Prevents overly greedy matching
- Reduces ReDoS attack surface
- Validates URL structure
- Prevents data leakage
- Blocks malformed URL injection
- Improves log integrity

---

## Exercise 2: Zip Code Regex - Missing Hyphen Validation

### Insecure Code

```java
import java.util.regex.*;
import java.util.Scanner;

public class ZipCode {
    public static void main(String[] args) {

        try (Scanner scanner = new Scanner(System.in)) {

            Pattern zipPattern = Pattern.compile("^\\d{5}(\\d{4})?$");
            System.out.println("Enter a Zipcode as xxxxx or xxxxx-xxxx: ");
            String zipCode = scanner.nextLine();

            if ( !zipPattern.matcher(zipCode).matches() ) {
                System.out.println("Incorrect Zipcode");
            }
            else {
                System.out.println("Correct Zip");
            }
        }
    }
}
```

### Identification of Regex Issue

The regex pattern is: `^\\d{5}(\\d{4})?$`

### Security Risk

**What it checks incorrectly:**

The pattern accepts 9-digit zip codes WITHOUT a hyphen (e.g., `123456789`), but the user prompt specifies the format must be `xxxxx` or `xxxxx-xxxx` with a hyphen.

**Security risks:**

1. **Format inconsistency:** Accepting `123456789` when expecting `12345-6789` causes data inconsistency
2. **Database issues:** Storing zip codes in different formats makes searching/indexing difficult
3. **Validation bypass:** Users can submit malformed data that passes validation
4. **Integration problems:** External APIs expecting standard format may reject the data
5. **User confusion:** Accepting multiple formats when only specific format is requested
6. **Data quality:** Inconsistent formats reduce data integrity and reliability

### Corrected Code

```java
import java.util.regex.*;
import java.util.Scanner;

public class ZipCode {
    public static void main(String[] args) {

        try (Scanner scanner = new Scanner(System.in)) {

            // Corrected pattern: requires hyphen for extended zip code
            Pattern zipPattern = Pattern.compile("^\\d{5}(-\\d{4})?$");
            
            System.out.println("Enter a Zipcode as xxxxx or xxxxx-xxxx: ");
            String zipCode = scanner.nextLine();

            if ( !zipPattern.matcher(zipCode).matches() ) {
                System.out.println("Incorrect Zipcode");
            }
            else {
                System.out.println("Correct Zip");
            }
        }
    }
}
```

### Explanation of Fix

The corrected regex pattern `^\\d{5}(-\\d{4})?$` properly validates zip codes:

**Pattern breakdown:**
- `^` - Start of string anchor
- `\\d{5}` - Exactly 5 digits (required)
- `(-\\d{4})?` - Optional group containing:
  - `-` - Required hyphen separator
  - `\\d{4}` - Exactly 4 digits
- `$` - End of string anchor

**What this accepts:**
- `12345` ✓ (5-digit zip)
- `12345-6789` ✓ (9-digit zip with hyphen)

**What this rejects:**
- `123456789` ✗ (9 digits without hyphen)
- `12345-678` ✗ (incomplete extension)
- `1234-5678` ✗ (hyphen in wrong position)
- `12345 6789` ✗ (space instead of hyphen)

**Security improvements:**
- Enforces consistent format matching user prompt
- Prevents data inconsistency
- Improves database integrity
- Ensures compatibility with external systems
- Reduces user confusion
- Maintains data quality standards
- Prevents validation bypass

---

## Exercise 3: Phone Number Regex - Multiple Pattern Errors

### Insecure Code

```html
<!DOCTYPE html>
<!-- HTML Form to validate a phone number --> 
<html>
<head>
<style>
    input:invalid {border: red solid 3px;}
</style>
</head>

<p>
  <label>
    Enter your phone number in the format 123-456-7890
    <input
      name="tel1"
      type="tel"
      pattern="[0-9]{4}"
      placeholder="###"
      aria-label="3-digit area code"
      size="2" 
    />
    -
    <input
      name="tel2"
      type="tel"
      pattern="\d{3}"
      placeholder="###"
      aria-label="3-digit prefix"
      size="2" 
    />
    -
    <input
      name="tel3"
      type="tel"
      pattern="\D{4}"
      placeholder="####"
      aria-label="4-digit number"
      size="3" 
    />
  </label>
</p>
</html>
```

### Identification of Regex Issues

The code contains three regex patterns:
1. `pattern="[0-9]{4}"` (field 1)
2. `pattern="\d{3}"` (field 2)
3. `pattern="\D{4}"` (field 3)

### Security Risk

**What's missing and what's checked incorrectly:**

**Field 1 Issues:**
- Pattern `[0-9]{4}` expects 4 digits but should expect 3 (area code)
- Placeholder shows `###` (3 digits) but validates for 4

**Field 2 Issues:**
- Pattern `\d{3}` is correct (3 digits)
- No major issues with this field

**Field 3 Issues:**
- Pattern `\D{4}` uses `\D` (NON-DIGIT) instead of `\d` (DIGIT)
- `\D` matches any character that is NOT a digit
- Accepts letters, symbols, spaces instead of numbers
- Critical validation error

**Security risks:**

1. **Data corruption:** Field 1 accepts 4-digit area codes (invalid in North America)
2. **Validation bypass:** Field 3 accepts non-numeric input like "abcd" or "!@#$"
3. **Injection attacks:** Special characters in phone number fields could enable:
   - SQL injection if improperly sanitized
   - Command injection in automated dialing systems
   - Script injection in call logs
4. **Database issues:** Inconsistent data formats break phone number validation
5. **Communication failures:** Invalid phone numbers can't be called
6. **PII leakage:** Malformed data may bypass GDPR/privacy sanitization
7. **Fraud:** Fake phone numbers enable account creation abuse

### Corrected Code

```html
<!DOCTYPE html>
<!-- HTML Form to validate a phone number --> 
<html>
<head>
<style>
    input:invalid {border: red solid 3px;}
</style>
</head>

<p>
  <label>
    Enter your phone number in the format 123-456-7890
    <input
      name="tel1"
      type="tel"
      pattern="[0-9]{3}"
      placeholder="###"
      aria-label="3-digit area code"
      size="2" 
      required
    />
    -
    <input
      name="tel2"
      type="tel"
      pattern="[0-9]{3}"
      placeholder="###"
      aria-label="3-digit prefix"
      size="2" 
      required
    />
    -
    <input
      name="tel3"
      type="tel"
      pattern="[0-9]{4}"
      placeholder="####"
      aria-label="4-digit number"
      size="3" 
      required
    />
  </label>
</p>
</html>
```

### Explanation of Fix

The corrected code fixes all validation issues:

**Field 1 (Area Code):**
- Changed from `[0-9]{4}` to `[0-9]{3}`
- Now correctly validates 3-digit area code
- Matches the format specification (123-456-7890)

**Field 2 (Prefix):**
- Changed from `\d{3}` to `[0-9]{3}` for consistency
- Both patterns work, but `[0-9]` is more explicit in HTML
- Maintains correct 3-digit validation

**Field 3 (Line Number):**
- Changed from `\D{4}` (non-digits) to `[0-9]{4}` (digits)
- Now correctly validates 4-digit line number
- Prevents acceptance of non-numeric characters

**Additional improvements:**
- Added `required` attribute to all fields for mandatory validation
- Consistent pattern syntax across all fields (`[0-9]` instead of mix)
- Properly validates North American phone format

**Security improvements:**
- Enforces numeric-only input
- Prevents injection of special characters
- Validates proper phone number structure
- Blocks formation of invalid phone numbers
- Ensures data consistency
- Reduces fraud and abuse potential
- Protects against downstream injection attacks

---

## Exercise 4: Date Regex - Multiple Validation Errors

### Insecure Code

```python
import re

def validate_date(date_str):
    pattern = r"^(1[1-9]|1[0-2])/(0[1-9][12][0-9]|3[01])/\w{4}$"
    
    # Check if the date matches the pattern
    if re.match(pattern, date_str):
        print("Valid date format.")
    else:
        print("Invalid date format. Please enter the date in the format MM/DD/YYYY.")

date_input = input("Please enter a date in the format MM/DD/YYYY: ")
validate_date(date_input)
```

### Identification of Regex Issue

The regex pattern is: `r"^(1[1-9]|1[0-2])/(0[1-9][12][0-9]|3[01])/\w{4}$"`

### Security Risk

**Three errors in the regex:**

**Error 1: Month validation `(1[1-9]|1[0-2])`**
- Only accepts months 11-12 (`1[1-9]` matches 11-19, `1[0-2]` matches 10, 11, 12)
- Missing months 01-09
- Rejects valid dates in first 9 months of the year

**Error 2: Day validation `(0[1-9][12][0-9]|3[01])`**
- Pattern `0[1-9][12][0-9]` has syntax error - missing alternation operator
- Should be `0[1-9]|[12][0-9]` to match days 01-29
- Current pattern matches invalid sequences like "0112", "0229"

**Error 3: Year validation `\w{4}`**
- `\w` matches alphanumeric characters AND underscores [a-zA-Z0-9_]
- Accepts invalid years like "abcd", "20_3", "YYYY"
- Should only accept digits

**Security risks:**

1. **Validation bypass:** Accepting letters in year field allows:
   - SQL injection via date fields ("20'; DROP TABLE--")
   - XSS attacks in date display
   - Command injection in date processing
   - Log injection with special characters

2. **Data corruption:** Invalid dates corrupt databases and analytics

3. **Logic errors:** Business logic relying on valid dates fails

4. **DoS attacks:** Processing invalid dates may cause application crashes

5. **Compliance violations:** GDPR/HIPAA require accurate timestamps

6. **Authentication bypass:** Date-based access controls bypassed with invalid dates

### Corrected Code

```python
import re

def validate_date(date_str):
    # Corrected pattern with all three errors fixed
    pattern = r"^(0[1-9]|1[0-2])/(0[1-9]|[12][0-9]|3[01])/\d{4}$"
    
    # Check if the date matches the pattern
    if re.match(pattern, date_str):
        print("Valid date format.")
    else:
        print("Invalid date format. Please enter the date in the format MM/DD/YYYY.")

date_input = input("Please enter a date in the format MM/DD/YYYY: ")
validate_date(date_input)
```

### Explanation of Fix

The corrected pattern `^(0[1-9]|1[0-2])/(0[1-9]|[12][0-9]|3[01])/\d{4}$` fixes all three errors:

**Fix 1: Month validation `(0[1-9]|1[0-2])`**
- `0[1-9]` - Matches 01-09 (months January-September)
- `1[0-2]` - Matches 10-12 (months October-December)
- Now accepts all 12 valid months

**Fix 2: Day validation `(0[1-9]|[12][0-9]|3[01])`**
- `0[1-9]` - Matches 01-09
- `[12][0-9]` - Matches 10-19, 20-29
- `3[01]` - Matches 30-31
- Properly validates days 01-31 with correct alternation

**Fix 3: Year validation `\d{4}`**
- `\d{4}` - Matches exactly 4 digits (0-9 only)
- Rejects letters, underscores, and special characters
- Ensures numeric year values only

**Pattern breakdown:**
- `^` - Start anchor
- `(0[1-9]|1[0-2])` - Month: 01-12
- `/` - Literal slash separator
- `(0[1-9]|[12][0-9]|3[01])` - Day: 01-31
- `/` - Literal slash separator
- `\d{4}` - Year: 4 digits
- `$` - End anchor

**Valid examples:**
- `01/15/2024` ✓
- `12/31/2023` ✓
- `06/01/2025` ✓

**Invalid examples:**
- `13/01/2024` ✗ (month > 12)
- `06/32/2024` ✗ (day > 31)
- `01/15/abcd` ✗ (non-numeric year)
- `1/5/2024` ✗ (missing leading zeros)

**Security improvements:**
- Prevents injection attacks via year field
- Ensures data type consistency
- Blocks malformed date input
- Validates proper date format
- Protects against downstream vulnerabilities
- Maintains data integrity

**Note:** This regex validates format only, not logical date validity (e.g., doesn't check if February 31 exists). For production use, additional validation should verify the date is logically valid for the calendar.

---

## Exercise 5: Filename Regex - Multiple Pattern Errors

### Insecure Code

```python
import re

def validate_filename(filename):
    # Regular expression pattern for a filename with an extension
    pattern = r"^[\s]+\.(java,py,cs,txt)$"
    
    # Check if the filename matches the pattern
    if re.match(pattern, filename):
        print("Valid filename format.")
    else:
        print("Invalid filename format. Please enter a filename with an extension.")

filename_input = input("Please enter a filename containing code with one of the following extensions: java, py, cs, txt")
validate_filename(filename_input)
```

### Identification of Regex Issue

The regex pattern is: `r"^[\s]+\.(java,py,cs,txt)$"`

### Security Risk

**Four errors in the regex:**

**Error 1: Filename character class `[\s]+`**
- `\s` matches WHITESPACE characters (spaces, tabs, newlines)
- Only accepts filenames made entirely of whitespace
- Rejects all valid filenames with actual characters
- Should use `[a-zA-Z0-9_-]+` or `\S+` for filename characters

**Error 2: Literal dot not escaped `\.`**
- The `.` should be escaped as `\.` but it is correctly escaped in the code
- Actually, this is correct - not an error

**Error 2 (Actual): Extension group syntax `(java,py,cs,txt)`**
- Uses commas instead of pipe `|` for alternation
- `(java,py,cs,txt)` matches the literal string "java,py,cs,txt"
- Should be `(java|py|cs|txt)` for OR logic
- Accepts only files like "   .java,py,cs,txt"

**Error 3: Missing proper filename characters**
- No provision for actual alphanumeric filename characters
- Only matches whitespace before extension

**Error 4: No minimum filename length**
- Should require at least one character for filename
- Pattern structure fundamentally broken

**Security risks:**

1. **Path traversal:** Without proper filename validation, attackers can use:
   - `../../etc/passwd.txt` to access system files
   - `..\windows\system32\config.txt` on Windows
   - Bypass directory restrictions

2. **File upload vulnerabilities:**
   - Accepting only whitespace filenames causes file system errors
   - Could overwrite files with similar whitespace-based names
   - Enable denial-of-service by filling directories

3. **Command injection:** Improper filename validation enables:
   - `; rm -rf /.txt` (command injection)
   - `$(malicious_command).py` (command substitution)
   - Special characters in filenames execute commands

4. **Extension bypass:** Incorrect extension validation allows:
   - Execution of malicious file types
   - Upload of executable files (.exe, .sh, .bat)
   - Webshell uploads (.php, .jsp, .aspx)

5. **Directory traversal in extensions:**
   - Pattern doesn't prevent `file.java/../../etc/passwd`

### Corrected Code

```python
import re

def validate_filename(filename):
    # Corrected pattern with all four errors fixed
    pattern = r"^[a-zA-Z0-9_-]+\.(java|py|cs|txt)$"
    
    # Check if the filename matches the pattern
    if re.match(pattern, filename):
        print("Valid filename format.")
    else:
        print("Invalid filename format. Please enter a filename with an extension.")

filename_input = input("Please enter a filename containing code with one of the following extensions: java, py, cs, txt: ")
validate_filename(filename_input)
```

### Explanation of Fix

The corrected pattern `^[a-zA-Z0-9_-]+\.(java|py|cs|txt)$` fixes all errors:

**Fix 1: Proper filename characters `[a-zA-Z0-9_-]+`**
- `[a-zA-Z0-9_-]` - Character class accepting letters, numbers, underscores, hyphens
- `+` - Requires at least one character (prevents empty filenames)
- Rejects whitespace-only names
- Prevents path traversal characters (/, \, ., etc.)

**Fix 2: Correct extension alternation `(java|py|cs|txt)`**
- Uses pipe `|` instead of commas for OR logic
- Matches any single extension: java OR py OR cs OR txt
- Proper regex group syntax

**Fix 3: Properly escaped dot `\.`**
- Escapes the literal period before extension
- Prevents matching any character (unescaped `.`)

**Fix 4: Anchors prevent directory traversal**
- `^` and `$` ensure entire string is validated
- Prevents partial matches like `../../file.txt`
- Blocks null bytes and path separators

**Pattern breakdown:**
- `^` - Start anchor (no leading path)
- `[a-zA-Z0-9_-]+` - One or more valid filename characters
- `\.` - Literal period (extension separator)
- `(java|py|cs|txt)` - One of the four allowed extensions
- `$` - End anchor (no trailing path or characters)

**Valid examples:**
- `HelloWorld.java` ✓
- `my_script.py` ✓
- `Program-1.cs` ✓
- `README.txt` ✓

**Invalid examples:**
- `   .java` ✗ (whitespace filename)
- `file.java,py,cs,txt` ✗ (wrong extension format)
- `../../passwd.txt` ✗ (path traversal)
- `script.sh` ✗ (invalid extension)
- `file name.py` ✗ (contains space)
- `.java` ✗ (no filename)
- `file.` ✗ (no extension)

**Security improvements:**
- Prevents path traversal attacks
- Blocks command injection via filenames
- Validates allowed extension types only
- Ensures filename has proper structure
- Rejects special characters that could be dangerous
- Protects file system integrity
- Prevents directory traversal
- Enforces whitelist of safe extensions

**Additional security considerations for production:**
```python
import re
import os

def validate_filename_secure(filename):
    # Basic pattern validation
    pattern = r"^[a-zA-Z0-9_-]+\.(java|py|cs|txt)$"
    
    if not re.match(pattern, filename):
        return False
    
    # Additional security checks
    # 1. Check for null bytes
    if '\0' in filename:
        return False
    
    # 2. Normalize path and check for traversal
    normalized = os.path.normpath(filename)
    if normalized != filename or '/' in filename or '\\' in filename:
        return False
    
    # 3. Length validation (prevent DoS)
    if len(filename) > 255:
        return False
    
    # 4. Check for reserved names (Windows)
    reserved = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'LPT1']
    basename = filename.split('.')[0].upper()
    if basename in reserved:
        return False
    
    return True
```

---

## License

Educational purposes for SDEV245 coursework.
