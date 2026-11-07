# Scoring

1. **Weight** of a signal = strength x reliability.
2. **Category score** = 1 - product of (1 - weight) over the signals in that category, so repeats give diminishing returns.
3. **Base risk** = the same combination across categories, with each category scaled by 0.6 so a single category cannot reach the top alone.
4. **Chain bonus.** A category counts as present at 0.35 or more. If the present categories complete a scam chain (`data/chains.json`), risk moves toward 1 by that chain's bonus.
5. **Dampeners** (for example an official-domain match) reduce risk, capped at 0.40, and at 0.15 when a full chain is present, so one real link cannot hide a scam script.
6. **Levels:** under 0.30 Low signals, under 0.65 Suspicious, under 0.85 High risk, otherwise Critical.