---
name: wazuh-triagem
description: Triage panel for Wazuh alerts, built as a rack of air-traffic control strips in a night operations room.
colors:
  chao: "#13202a"
  chao-fundo: "#0e1820"
  baia: "#16252f"
  painel: "#1b2d3a"
  painel-alto: "#223849"
  bloco-borda: "#2b4052"
  filete: "#26394a"
  filete-forte: "#3c5568"
  texto: "#e8eef2"
  texto-2: "#b3c2cd"
  texto-3: "#93a8b7"
  titulo-creme: "#f4ecd8"
  faixa: "#e6d9b8"
  faixa-recuada: "#d6c9a6"
  faixa-acesa: "#efe5c9"
  faixa-borda: "#c4b692"
  faixa-tinta: "#1b242b"
  faixa-chave: "#5a503f"
  faixa-decidida: "#c5d0d6"
  faixa-decidida-borda: "#a5b3bb"
  faixa-decidida-chave: "#46525a"
  foco: "#f0a43a"
  critico: "#c53a3a"
  alto: "#b4531f"
  medio: "#806716"
  baixo: "#4f6f82"
  carimbo: "#22598a"
  carimbo-descarte: "#7a3b34"
  nao-confiavel: "#e0907a"
  perigo: "#f08a80"
  perigo-fundo: "#3a1f22"
typography:
  display:
    fontFamily: "B612 Mono, ui-monospace, monospace"
    fontSize: "34px"
    fontWeight: 700
    lineHeight: 1
    fontFeature: "tnum"
  headline:
    fontFamily: "B612, system-ui, sans-serif"
    fontSize: "22px"
    fontWeight: 700
    lineHeight: 1.25
  title:
    fontFamily: "B612, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 700
    lineHeight: 1.45
  body:
    fontFamily: "B612, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.45
  body-small:
    fontFamily: "B612, system-ui, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.45
  label:
    fontFamily: "B612, system-ui, sans-serif"
    fontSize: "11px"
    fontWeight: 400
    lineHeight: 1.45
    letterSpacing: "0.06em"
  mono:
    fontFamily: "B612 Mono, ui-monospace, monospace"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.55
    fontFeature: "tnum"
rounded:
  none: "0px"
spacing:
  strip-gap: "6px"
  sm: "8px"
  md: "12px"
  lg: "18px"
  bay-gap: "26px"
  gutter: "28px"
components:
  button-primary:
    backgroundColor: "{colors.faixa}"
    textColor: "{colors.faixa-tinta}"
    rounded: "{rounded.none}"
    padding: "0 16px"
    height: "40px"
  button-primary-hover:
    backgroundColor: "{colors.faixa-acesa}"
  button:
    backgroundColor: "transparent"
    textColor: "{colors.texto}"
    rounded: "{rounded.none}"
    padding: "0 16px"
    height: "40px"
  button-hover:
    backgroundColor: "{colors.painel-alto}"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.texto-2}"
    rounded: "{rounded.none}"
    padding: "0 16px"
    height: "40px"
  input:
    backgroundColor: "{colors.chao-fundo}"
    textColor: "{colors.texto}"
    rounded: "{rounded.none}"
    padding: "9px 12px"
    height: "40px"
  tab-active:
    backgroundColor: "{colors.painel}"
    textColor: "{colors.titulo-creme}"
    rounded: "{rounded.none}"
    padding: "0 14px"
    height: "36px"
  toggle-pressed:
    backgroundColor: "{colors.faixa}"
    textColor: "{colors.faixa-tinta}"
    rounded: "{rounded.none}"
  strip:
    backgroundColor: "{colors.faixa}"
    textColor: "{colors.faixa-tinta}"
    rounded: "{rounded.none}"
    height: "66px"
  strip-open:
    backgroundColor: "{colors.faixa-acesa}"
  strip-recessed:
    backgroundColor: "{colors.faixa-recuada}"
  strip-decided:
    backgroundColor: "{colors.faixa-decidida}"
    textColor: "{colors.faixa-tinta}"
  designator-large:
    textColor: "#ffffff"
    typography: "{typography.display}"
    size: "76px"
  stamp:
    backgroundColor: "transparent"
    textColor: "{colors.carimbo}"
    rounded: "{rounded.none}"
    padding: "1px 7px"
  stamp-discard:
    textColor: "{colors.carimbo-descarte}"
  block:
    backgroundColor: "{colors.painel}"
    textColor: "{colors.texto}"
    rounded: "{rounded.none}"
    padding: "16px 18px 18px"
  evidence-log:
    backgroundColor: "{colors.chao-fundo}"
    textColor: "#ece4cf"
    typography: "{typography.mono}"
    rounded: "{rounded.none}"
    padding: "12px 14px"
---

# Design System: wazuh-triagem

## Overview

**Creative North Star: "Faixas de Controle"**

An operations room at night: a dark petrol ground, a rack of buff paper flight-progress strips, and a controller who pulls the active strip out of the rack, works it, stamps it, and lets it slide into the Decided bay. Every alert is a strip with fixed fields (level designator, rule and agent, origin, time and state), so the eye learns one silhouette and reads the queue by position, not by hunting through a table.

The surface is dense and quiet. Colour is flat and does structural work: the paper strips are the only light objects on the dark floor, the level designator is the only saturated block on a strip, and amber appears only where the operator's attention is. Depth comes from tone and 1px rules, never from shadow, glow, glass or gradient. Corners are square everywhere. Motion is physical and rare: the decided strip travels between bays, and the stamp lands once.

Rejected: the SIEM default of a blue data table with a flyout of rounded cards.

**Key Characteristics:**
- Buff paper strips on a petrol ground; the strip is the unit of the whole interface.
- Flat colour, square corners, 1px rules; no shadow, glow, glass or gradient.
- Amber is attention only: focus, the open strip, the text caret.
- B612 for everything, B612 Mono for figures, IPs, times and logs.
- Decisions are stamps; overridden values are struck through, never removed.
- Attacker-controlled text is boxed, dashed and labelled.

## Colors

A night palette of petrol greys under buff paper, with one amber for attention, a fixed four-step level ramp, and ink-coloured stamps.

### Primary
- **Strip Buff** (faixa): the paper of every pending strip, the primary button, the pressed state of toggles and filters, and the count chip on the Queue tab. It is the "lit object" of the room; nothing else large is this light.
- **Strip Ink** (faixa-tinta): all text on buff paper, and the inverted primary button on the Connect strip.
- **Field Key Brown** (faixa-chave): the small uppercase field keys printed on a strip.
- **Lit Strip** (faixa-acesa) and **Recessed Strip** (faixa-recuada): hover/open and "not the open one" states of a strip. When a strip is open, every other strip recedes a step.
- **Strip Edge** (faixa-borda): strip outline and the 1px rules between strip fields.

### Secondary
- **Decided Grey-Blue** (faixa-decidida, with faixa-decidida-borda and faixa-decidida-chave): the paper of strips in the Decided bay, and the backing fill behind stamps so they read as ink on paper.
- **Stamp Blue** (carimbo): approved and corrected stamps.
- **Stamp Oxblood** (carimbo-descarte): discarded stamps, so a discarded alert reads apart from accepted ones at a glance.

### Tertiary
- **Signal Amber** (foco): focus outline (2px, offset 2px), the open strip's 3px outline, focused field borders, and the text caret. The text-selection highlight is a dark amber (#7a5a24 on #fff8ec).
- **Level Ramp** (critico, alto, medio, baixo): the designator block fill by rule level: 0-4 baixo (slate blue), 5-7 medio (dark olive gold), 8-11 alto (burnt orange), 12-15 critico (red). The same ramp fills the importance column of Feedback records. White text on all four.
- **Untrusted Salmon** (nao-confiavel): the dashed border and label of attacker-controlled text. Used for nothing else.
- **Danger** (perigo, on perigo-fundo): API offline, errors, bad reputation figures, quarantine seals, and the manipulation warning band. On buff paper the danger tone is a dark red (#8f2420).

### Neutral
- **Petrol Floor** (chao): page ground and the open-alert pane.
- **Deep Floor** (chao-fundo): top bar, decision bar, input wells, evidence log, the key rail of the comparison.
- **Rack Bay** (baia): the strip rack and the Connect stage.
- **Panel** (painel) and **Panel Raised** (painel-alto): content blocks; raised is button hover.
- **Block Edge** (bloco-borda): the outline of blocks and Feedback records.
- **Rule** (filete) and **Strong Rule** (filete-forte): 1px dividers; strong rules outline buttons, inputs and segmented controls.
- **Text** (texto), **Text 2** (texto-2), **Text 3** (texto-3): primary, secondary and tertiary text on the dark ground.
- **Title Cream** (titulo-creme): brand, headings and final decided values on the dark ground; a warm paper-white so headings belong to the same room as the strips.

### Named Rules
**The Amber Is Attention Rule.** Signal Amber marks only where the operator is: focus, the open strip, the caret. It never decorates, never fills a button, never colours a status.

**The Fixed Ramp Rule.** A rule level always maps to the same band (0-4, 5-7, 8-11, 12-15) and the same colour on every screen. Do not add bands or reuse ramp colours for anything except level and importance.

**The Ink Stamp Rule.** Accepted decisions (approved, corrected) are Stamp Blue; a discard is Stamp Oxblood. Stamps are the only place those colours appear.

## Typography

**Display Font:** B612 Mono (with ui-monospace, monospace)
**Body Font:** B612 (with system-ui, sans-serif)
**Label/Mono Font:** B612 Mono, tabular figures

**Character:** B612 was drawn for aircraft cockpit displays: open apertures, unambiguous glyphs, built for reading at a glance under pressure. The mono cut carries every figure, IP, timestamp and log so columns align; its wide punctuation gives times and IPs an instrument-readout cadence. Both faces are self-hosted at 400 and 700 only.

### Hierarchy
- **Display** (B612 Mono 700, 34px, line-height 1): the large designator number and the reputation figures. The strip designator uses the same face at 24px.
- **Headline** (B612 700, 22px, 1.25): the open alert's title, the Feedback heading, the Connect heading. Drops to 19px under 860px.
- **Title** (B612 700, 15px): bay headings and block-level emphasis; final values on the comparison rail; the analysis summary at 400. Blocks head at 14px 700.
- **Body** (B612 400, 14px, 1.45): base text; strip values. Prose measures are capped at 68-80ch.
- **Body Small** (B612 400, 13px): meta lines, secondary lines, hints, field labels on forms.
- **Label** (B612 400, 11px, letter-spacing 0.04-0.06em, uppercase): strip field keys and the key rail (CLASSIFICAÇÃO, SEVERIDADE, AÇÃO), record definition terms. These are the printed fields of the strip, not section eyebrows.
- **Mono** (B612 Mono 400, 13px, 1.55): the evidence log, IPs, times, counts, model names, kbd hints at 11px.

### Named Rules
**The Readout Rule.** Any figure, IP, timestamp, count or log goes in B612 Mono with tabular numbers. Words stay in B612.

**The Two Weights Rule.** Only 400 and 700 exist. Hierarchy comes from size, weight and the cream-versus-grey text ramp, not from more weights.

## Layout

A fixed-chrome workstation. A 56px top bar (brand, Queue/Feedback tabs, search, API status, PT/EN, sign out) sits over a two-column floor: the rack on the left (minmax(520px, 600px)) and the open alert on the right, with a decision bar fixed to the bottom of the right pane. Only the rack and the alert body scroll; the bars never move.

The rack holds two bays (Pending above Decided, 26px apart). Strips stack with a 6px gap, each a four-column grid: designator (60px), rule and agent (flexible), origin (150px), time and state (132px). Every strip row reserves 14px on the right so the open strip can be pulled 14px out of the rack.

The open alert stacks a header (large designator, title, meta line separated by 1px rules), then a two-column grid (1.15fr / 1fr, 18px gap) of blocks: Evidence beside Reputation, then the AI-versus-final comparison spanning both columns. Gutters are 28px; block padding is 16-18px.

Rhythm is a small set of steps: 6px (strip gap), 8px and 12px (inner gaps), 18px (block padding and grid gaps), 26-28px (bay separation and pane gutters).

**Below 1180px:** the rack narrows to 400-440px, the strip drops its origin column (the IP moves up into the rule line), the alert grid becomes one column, and kbd hints leave the decision bar except on the icon-only Previous button.

**Below 860px:** one pane at a time. The rack is the queue view; opening an alert hides the rack and shows a Back control. The top bar becomes a two-row grid. The open strip is pulled 8px instead of 14px. The decision actions become a three-up grid of equal buttons, and all kbd hints are hidden.

## Elevation & Depth

The system is flat. There are no shadows anywhere. Depth is tonal: Deep Floor for bars and wells, Petrol Floor for the working ground, Rack Bay for the rack, Panel for blocks, and the buff strips as the lightest plane. Edges are 1px rules. The one spatial gesture is lateral, not vertical: the open strip slides 14px out of the rack and takes an amber outline, while its neighbours recede one tone.

### Named Rules
**The Flat Room Rule.** No box-shadow, glow, blur, glass or gradient. A surface is separated by a tone step or a 1px rule, nothing else.

**The Pulled Strip Rule.** The active item is shown by pulling it out of the rack (translateX 14px; 8px under 860px) with an amber outline, never by lifting it.

## Shapes

Every corner is square (0px): strips, blocks, buttons, inputs, tabs, chips, seals and stamps. Borders are 1px solid, with three deliberate exceptions that carry meaning: a 1px dashed border marks an empty bay or empty list (a slot with nothing in it), a 1px dashed salmon border marks untrusted text, and stamps use a 2px (3px large) border with a -4deg tilt, like a rubber stamp. Inside a strip and on the comparison rail, fields are divided by 1px vertical rules, the way a paper strip is ruled into boxes. List bullets are 7px by 1px dashes, not dots.

## Components

### Buttons
Rectangular, outlined, tactile.
- **Shape:** square (0px), 40px minimum height, 0 16px padding, 8px gap between icon and label.
- **Primary:** Strip Buff fill with Strip Ink text, 700. One primary per bar (Approve, or Analyse before an analysis exists). Hover lifts to Lit Strip.
- **Default:** transparent with a 1px Strong Rule outline and Text colour; hover fills Panel Raised.
- **Ghost:** no outline, Text 2, brightening to Text on hover (Cancel, Previous).
- **Press:** translateY(1px) for 0.1s. **Disabled:** 50% opacity, not-allowed cursor.
- **Focus:** 2px amber outline, 2px offset.
- **Key hints:** a kbd box (1px currentColor outline, 11px mono, 75% opacity) trails the label: A, C, D, J, K, I.
- **Icons:** Phosphor, bold weight, 16px in buttons.

### Chips and Segmented Controls
- **Tabs:** 36px tall, 0 14px padding, Text 2; the current tab fills Panel with a Strong Rule outline and Title Cream text. The Queue tab carries a buff count chip with ink figures.
- **Segmented toggles** (PT/EN, Feedback filters): one Strong Rule outline around the group, 1px rules between segments; the pressed segment fills Strip Buff with ink, 700.
- **Seals and MITRE tags:** 1px outline in currentColor or Strong Rule, 2px 8px padding, 12px.

### Cards / Containers
- **Corner Style:** square (0px).
- **Background:** Panel, with a 1px Block Edge outline. Quarantined Feedback records shift to a muted plum-grey with a reddish edge.
- **Shadow Strategy:** none (see Elevation & Depth).
- **Internal Padding:** 16px 18px 18px; block headings at 14px 700 with 12px below.
- **Empty states:** a 1px dashed Strong Rule box with Text 2, plus an optional mono hint line.

### Inputs / Fields
- **Style:** Deep Floor well, 1px Strong Rule outline, square, 40px minimum height, 9px 12px padding. Label above at 13px Text 2; help below at 12px Text 3; error at 13px Danger.
- **Focus:** the border turns Signal Amber; no glow. The search box turns its border amber on focus-within.
- **On paper:** on the Connect strip, inputs invert to a pale paper well (#f6efdc) with a darker buff edge, and errors use the dark paper red.

### Navigation
The top bar on Deep Floor with a 1px rule below; brand in Title Cream 700 at 17px; tabs as above; API status at 13px with a plugs icon, turning Danger when offline. Under 860px the bar becomes two rows and the status hides unless the API is down.

### The Strip (signature component)
A full-width button, 66px tall, Strip Buff with a 1px Strip Edge outline, ruled into four fields. Each field has an 11px uppercase key in Field Key Brown above a 14px value. The left field is the **Designator**: the level band colour with a white mono number and a 15-tick **Magnitude** scale below it (2px by 6px ticks, lit white up to the level, 30% white beyond). States: hover and open use Lit Strip; when one strip is open all others recede; the open strip takes a 3px amber outline and slides out 14px. Decided strips turn Decided Grey-Blue and show their stamp in the state field. Loading strips are flat dark blocks that pulse in opacity (0.55 to 1, 1.2s, alternating); no shimmer.

### The Stamp
11px 700 uppercase label, letter-spacing 0.08em, 2px border and text in the stamp colour, tilted -4deg, backed by Decided Grey-Blue. The large stamp (15px, 3px border, 4px 12px padding) sits in the open alert's header. Only the decision that just happened animates: the stamp drops in from scale 1.5, -12deg and transparent to rest at -4deg on a stiff spring (stiffness 520, damping 22). Earlier decisions arrive already stamped.

### The Slide to Decided
When a strip is decided it travels from the Pending bay to the Decided bay as one object (shared layout identity across both bays, spring stiffness 340, damping 34), then its stamp lands. This and the stamp are the system's only expressive motion; both are disabled when the user prefers reduced motion, as are strip transitions and skeleton pulses.

### The Key Rail (AI versus final)
Three columns: what the AI said (right-aligned, Text 2, 15px), a central key column on Deep Floor with 1px Strong Rule sides holding the 11px uppercase field name, and the final value (15px 700 Title Cream). Rows split with 1px rules. When policy or the analyst overrode a value, the AI value stays visible, struck through with a 2px line in Text 3. The manipulation warning is a flat Danger band above the rail with a bold octagon icon.

### Untrusted Evidence
Attacker-controlled log text sits in a Deep Floor box with a 1px dashed Untrusted Salmon border, 12px 14px padding, mono 13px, pre-wrapped, capped at 220px height with its own scroll. Above it, a 12px salmon label with a shield-warning icon states in words that the text was written by whoever produced the event.

## Do's and Don'ts

### Do:
- **Do** build every list of alerts from the Strip: buff paper, fixed ruled fields, designator on the left.
- **Do** keep every corner square (0px) and every edge a 1px rule.
- **Do** separate surfaces by tone steps (Deep Floor, Petrol Floor, Rack Bay, Panel, buff) instead of shadows.
- **Do** reserve Signal Amber (#f0a43a) for focus, the open strip and the caret.
- **Do** map rule level to the fixed four-band ramp, with the 15-tick magnitude scale, everywhere a level appears.
- **Do** show decisions as stamps: blue for approved and corrected, oxblood for discarded.
- **Do** strike through an overridden AI value and keep it on screen beside the final value.
- **Do** put attacker-controlled text in the dashed salmon box with its explicit label.
- **Do** set figures, IPs, times and logs in B612 Mono with tabular numbers.
- **Do** use Phosphor icons at bold weight, 14-18px, and CSS for any other mark (magnitude ticks, list dashes).
- **Do** gate every motion behind the user's reduced-motion preference; loading is a flat opacity pulse.

### Don't:
- **Don't** use box-shadow, glow, blur, glassmorphism or gradients, including on loading skeletons.
- **Don't** round corners.
- **Don't** use amber for status, emphasis, fills or decoration.
- **Don't** delete or hide an AI value the analyst or a policy overrode.
- **Don't** render attacker-controlled text without the untrusted treatment, and never as HTML.
- **Don't** fall back to the SIEM default of a blue data table with a flyout of rounded cards.
- **Don't** add font weights beyond 400 and 700, or a second type family.
- **Don't** ship raster images in the interface.
