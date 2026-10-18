"""Train the CRF NER.   python -m nlu.training.train_ner"""
import json
import sys

from ..config_loader import DEFAULT_DATA_DIR, DEFAULT_MODELS_DIR, load_configs
from ..features import Lexicons
from ..ner import CRFNER
from ..pipeline import CRF_MODEL_NAME
from ..schemas import MissingDependencyError


def main():
    ents, pats = load_configs()
    try:
        ner = CRFNER(Lexicons(ents, pats), pats["typo_lexicon"])
    except MissingDependencyError as e:
        print("ERROR:", e, file=sys.stderr)
        return 1
    train = json.loads((DEFAULT_DATA_DIR / "ner_train.json").read_text())
    meta = ner.train(train, DEFAULT_MODELS_DIR / CRF_MODEL_NAME)
    print("trained CRF:", json.dumps(meta))
    return 0


if __name__ == "__main__":
    sys.exit(main())
