# **App Name**: SecureFlow

*"In this heist, we're not stealing — we're protecting." SecureFlow casts every Pull Request as a member of the crew trying to reach The Vault (your codebase), with **The Professor** — SecureFlow's AI mastermind — checking credentials at the door before any breach gets through.*

## Core Features:

- **GitHub App Integration — The Inside Job**: Streamlined GitHub OAuth flow for repository selection and automated pull request webhook listeners. This is how the crew gets access to the building in the first place.
- **ArmorIQ Scanner — The Professor's Eyes**: High-fidelity security scan implementation that identifies hardcoded secrets, vulnerable dependencies, and insecure code patterns during PR cycles.
- **AI Reasoner Tool — The Professor's Voice**: An AI tool that applies logical reasoning to scanner findings to provide human-readable risk summaries and direct remediation advice in plain English, in-character as "The Professor."
- **ArmorIQ Policy Engine — The Plan**: Logic engine for automated risk evaluation, mapping findings to customizable policy states: Pass, Review Required, or Blocked.
- **Mission Control Dashboard**: Centralized workspace featuring high-level risk trends, PR status visualizations, and active vulnerability metrics built with shadcn/ui and Recharts.
- **Vault Logs — Audit Transparency**: A persistent audit trail stored in PostgreSQL for all automated security decisions, actions, and scanner results.
- **PR Status Reporter — The Getaway Signal**: Automated commit status updates and granular inline GitHub comments with direct feedback and action buttons.

## Style Guidelines:

- **Primary Color**: Vibrant Deep Violet (`#927BFF`) — providing a futuristic and high-tech feel that contrasts against deep surfaces, echoing the crew's iconic red against a shadowy palette.
- **Background Color**: Deep Graphite Charcoal (`#0C0B0F`) — a desaturated variation of the primary hue to create an immersive, distraction-free dark interface, like the inside of the Vault itself.
- **Accent Color**: Electric Azure (`#4D7BFF`) — an analogous hue that provides strong functional contrast for success states and interactive call-to-actions ("Audit Passed" moments).
- **Font Pairing**: 'Space Grotesk' (Sans-serif) for sharp, technical-feeling headlines and 'Inter' (Sans-serif) for clean, highly-readable UI controls and density-rich scan results.
- **Iconography**: Ultra-thin, mono-lineal strokes for icons, utilizing high-contrast borders to suggest precision and structural integrity — every line as deliberate as the heist itself.
- **Layout**: Spacious, container-less dashboard layout with high-blur background glass effects (Glassmorphism) to define hierarchy without visual clutter.
- **Motion**: Sophisticated micro-interactions using framer-motion, featuring rhythmic horizontal loaders that simulate continuous scanning pulses — The Professor, always watching.

## Narrative & Copy Guidelines:

Use these terms consistently across UI copy, docs, and marketing surfaces so the theme stays coherent app-wide:

| Theme Term | Refers To |
|---|---|
| The Professor | The AI security reasoner/persona behind explanations and remediation |
| The Vault | The codebase / protected repository |
| Mission Control | Main dashboard overview (`/dashboard`) |
| Breach Attempts | Security findings page (`/dashboard/findings`) |
| Defense Strategy | Policy management page (`/dashboard/policies`) |
| Vault Logs | Audit log page (`/dashboard/audit`) |
| The Resistance | SecureFlow's users/community defending their codebases |
| Bella Ciao | Tagline motif used for "all clear" / passed-audit moments |

Keep the tone confident and cinematic, never juvenile — SecureFlow is a serious security tool wearing a fun theme, not the other way around.