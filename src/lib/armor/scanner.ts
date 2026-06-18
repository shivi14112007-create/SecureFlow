import Groq from 'groq-sdk';

export type ScanFinding = {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  description: string;
  fileLocation: string;
  codeSnippet: string;
};

export interface FileChange {
  filename: string;
  patch: string;
}

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});

export class ArmorIQScanner {
  async scanPullRequest(files: FileChange[]): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];

    for (const file of files) {
      // Create a prompt specifically for vulnerability detection
      const prompt = `Analyze the following code changes (git patch) for security vulnerabilities.
Look for:
1. Hardcoded secrets.
2. Contextual leaks (e.g., logging process.env variables, exposing sensitive data to clients).
3. Logic flaws.

File: ${file.filename}
Patch:
${file.patch}

Respond ONLY in strictly valid JSON containing an array of findings. If no vulnerabilities exist, return an empty array [].
Format:
[{
  "type": "Data Leak | Vulnerability | Misconfig",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW",
  "description": "Detailed explanation of what the vulnerability is.",
  "fileLocation": "${file.filename}",
  "codeSnippet": "The specific problematic line(s) of code"
}]`;

      try {
        const chatCompletion = await groq.chat.completions.create({
          messages: [
            { role: 'system', content: 'You are an elite application security auditor. Output raw JSON only.' },
            { role: 'user', content: prompt }
          ],
          model: 'llama-3.3-70b-versatile',
          response_format: { type: 'json_object' },
        });

        const responseText = chatCompletion.choices[0]?.message?.content || '{"findings": []}';
        // Depending on how Groq formats the JSON object, you might need to extract an array
        const result = JSON.parse(responseText);
        const fileFindings = Array.isArray(result) ? result : (result.findings || []);
        
        findings.push(...fileFindings);

      } catch (error) {
        console.error(`Failed to scan file ${file.filename}:`, error);
      }
    }

    return findings;
  }
}

export const scanner = new ArmorIQScanner();