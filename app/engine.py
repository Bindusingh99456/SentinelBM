import time

def build_bad_char_table(pattern: str) -> dict:
    """
    Builds the Bad Character Heuristic table for the Boyer-Moore algorithm.
    """
    bad_char_table = {}
    pattern_len = len(pattern)
    
    # Store the index of the last occurrence of each character
    for i in range(pattern_len):
        bad_char_table[pattern[i]] = i
        
    return bad_char_table

def boyer_moore_scan(text: str, pattern: str, bad_char_table: dict) -> tuple[bool, dict]:
    """
    Performs the Boyer-Moore string matching using the Bad Character Heuristic.
    Returns a tuple (match_found, metrics_dict).
    Scans from right to left, short-circuiting when a match is found.
    """
    start_time = time.perf_counter()
    
    m = len(pattern)
    n = len(text)
    
    comparisons = 0
    skipped = 0
    match_found = False
    
    if m == 0 or m > n:
        end_time = time.perf_counter()
        return False, {
            "execution_time_ms": (end_time - start_time) * 1000,
            "comparisons": 0,
            "characters_skipped": 0
        }
        
    shift = 0
    while shift <= (n - m):
        j = m - 1
        
        # Keep reducing j while characters of pattern and text are matching at this shift
        while j >= 0:
            comparisons += 1
            if pattern[j] != text[shift + j]:
                break
            j -= 1
            
        # If pattern is present at current shift, j will become -1
        if j < 0:
            match_found = True
            # Short-circuit out as soon as threat signature is confirmed
            break
        else:
            # Shift the pattern so that the bad character in text aligns with its last occurrence in pattern.
            # If the character is not present in pattern, shift pattern past the mismatched character.
            bad_char = text[shift + j]
            bad_char_index = bad_char_table.get(bad_char, -1)
            
            # Max function ensures we don't shift backwards
            current_shift = max(1, j - bad_char_index)
            shift += current_shift
            skipped += (current_shift - 1) # Track how many characters we theoretically "skipped" vs a naive match step of 1
            
    end_time = time.perf_counter()
    metrics = {
        "execution_time_ms": (end_time - start_time) * 1000,
        "comparisons": comparisons,
        "characters_skipped": skipped
    }
    
    return match_found, metrics
