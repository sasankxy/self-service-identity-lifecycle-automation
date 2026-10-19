"""Train the custom TF-IDF + Naive Bayes intent model.   python -m nlu.training.train_intent"""
import json

from ..config_loader import DEFAULT_DATA_DIR, DEFAULT_MODELS_DIR, load_configs
from ..features import Lexicons
from ..intent_classifier import NaiveBayesIntentClassifier
from ..pipeline import NB_MODEL_NAME


def main():
    ents, pats = load_configs()
    nb = NaiveBayesIntentClassifier(Lexicons(ents, pats), ents, pats["typo_lexicon"])
    data = json.loads((DEFAULT_DATA_DIR / "intent_train.json").read_text())
    info = nb.train([d["text"] for d in data], [d["intent"] for d in data])
    nb.save(DEFAULT_MODELS_DIR / NB_MODEL_NAME)
    print("trained Naive Bayes:", json.dumps(info))


if __name__ == "__main__":
    main()
