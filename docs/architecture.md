# Architecture

`app.py` is the Streamlit UI. `detector.py` finds candidate values; `pseudonymizer.py` creates session labels; `sanitizer.py` replaces matches; `canary.py` measures complete-value leakage; `benchmark.py` runs three input conditions; `diagnosis.py` offers offline scoring and opt-in Ollama. Dataset fixtures are synthetic.
