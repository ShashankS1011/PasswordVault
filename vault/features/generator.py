# -*- coding: utf-8 -*-
"""Advanced password and passphrase generation (Improvement #34)."""
from __future__ import annotations

import secrets
import string
from typing import List, Tuple

# Ambiguous characters often misread on screen or paper
AMBIGUOUS_CHARS = "0O1lI|"

# Curated high-entropy wordlist for memorable passphrases
EFF_WORDLIST = [
    "abacus", "abbey", "abdomen", "ability", "abrupt", "absent", "absorb", "abstract",
    "academy", "accent", "accept", "access", "accident", "acclaim", "account", "accuracy",
    "achieve", "acoustic", "acquire", "action", "active", "actor", "adapt", "address",
    "adjust", "admire", "admit", "adopt", "advance", "adventure", "advice", "affair",
    "affect", "afford", "afraid", "agency", "agenda", "agent", "agility", "agree",
    "ahead", "aim", "airline", "airport", "alarm", "album", "alert", "algebra",
    "alien", "align", "alike", "alive", "alley", "alliance", "allow", "almond",
    "almost", "alpine", "already", "altar", "alter", "altitude", "aluminum", "always",
    "amateur", "amaze", "amber", "ambient", "ambition", "amend", "amplify", "anchor",
    "ancient", "android", "angel", "anger", "angle", "animal", "animate", "ankle",
    "announce", "annual", "answer", "antenna", "antique", "anxiety", "anyway", "apartment",
    "apology", "apostle", "apparel", "appeal", "appear", "apple", "appraise", "approve",
    "apron", "aquarium", "arcade", "arch", "archive", "arctic", "ardent", "area",
    "arena", "argue", "armor", "aroma", "around", "arrange", "array", "arrest",
    "arrival", "arrive", "arrow", "arsenal", "artery", "article", "artist", "ascend",
    "asphalt", "aspire", "assault", "assert", "assess", "asset", "assign", "assist",
    "assume", "assure", "astonish", "athlete", "atlas", "atom", "attach", "attack",
    "attain", "attempt", "attend", "attitude", "attract", "auction", "audit", "auditor",
    "aurora", "author", "autumn", "avail", "avalanche", "avenue", "average", "aviator",
    "avocado", "avoid", "awake", "award", "aware", "awesome", "axis", "aztec",
    "badge", "badger", "bagel", "baggage", "bakery", "balance", "balcony", "ballad",
    "balloon", "ballot", "bamboo", "banana", "bandit", "banner", "banquet", "barber",
    "bargain", "barrel", "barrier", "barter", "baseball", "basic", "basket", "battery",
    "battle", "bazaar", "beacon", "bead", "beaver", "beauty", "become", "bedrock",
    "beetle", "before", "beggar", "beginner", "behave", "behind", "believe", "bell",
    "bellow", "belong", "beloved", "bench", "benefit", "beret", "berry", "beside",
    "betray", "better", "between", "beyond", "bicycle", "binary", "biology", "birch",
    "bird", "biscuit", "bison", "bitter", "bizarre", "black", "blade", "blanket",
    "blaze", "blend", "bless", "blind", "blink", "bliss", "blizzard", "block",
    "blonde", "blossom", "blueprint", "blunt", "board", "boast", "bobcat", "boiler",
    "bold", "bolster", "bonanza", "bond", "bonfire", "bonnet", "bonus", "book",
    "boom", "boost", "border", "botany", "bother", "bottle", "bottom", "boulder",
    "bounce", "boundary", "bounty", "bouquet", "bowling", "bracket", "brain", "branch",
    "brand", "brass", "brave", "bread", "break", "breeze", "brick", "bridge",
    "brief", "bright", "brilliant", "brisk", "broad", "bronze", "brook", "broom",
    "brother", "bubble", "bucket", "buckle", "budget", "buffalo", "buffet", "builder",
    "bulb", "bullet", "bundle", "bunker", "burden", "bureau", "burn", "burst",
    "bushel", "business", "butter", "button", "buyer", "cabin", "cable", "cactus",
    "cadet", "cafe", "calendar", "calico", "calm", "camera", "camp", "campus",
    "canal", "canary", "cancel", "candle", "cannon", "canoe", "canvas", "canyon",
    "capable", "capital", "captain", "caption", "capture", "caravan", "carbon", "card",
    "careful", "cargo", "carousel", "carpet", "carriage", "carrier", "carrot", "carve",
    "cascade", "castle", "catalyst", "catch", "cater", "cathedral", "cause", "caution",
    "cavalry", "cavern", "cease", "cedar", "ceiling", "celebrate", "cellar", "cement",
    "cereal", "ceremony", "certain", "chain", "chair", "chalk", "chamber", "champion",
    "chance", "change", "channel", "chapel", "chapter", "charcoal", "chariot", "charm",
    "charter", "chase", "chateau", "check", "cheerful", "cheese", "chemist", "cherry",
    "chess", "chest", "chevron", "chick", "chief", "chimney", "chirp", "chisel",
    "chocolate", "choice", "choose", "chronic", "chubby", "cider", "cigar", "cinema",
    "circle", "circuit", "citizen", "citrus", "civic", "civil", "claim", "clam",
    "clarify", "classic", "clause", "clean", "clear", "clerk", "clever", "client",
    "cliff", "climate", "climb", "clinic", "clip", "cloak", "clock", "closet",
    "cloud", "clover", "clutch", "coach", "coastal", "cobra", "coffee", "cognition",
    "coherence", "collect", "college", "colony", "color", "column", "combine", "comet",
    "comfort", "command", "commence", "commerce", "compact", "compass", "compile", "complex",
    "compose", "compound", "compute", "concept", "concord", "concrete", "condor", "conduct",
    "confer", "conquest", "console", "constant", "construct", "consul", "contact", "contain",
    "content", "contour", "contract", "contrast", "convert", "convoy", "cookie", "copper",
    "coral", "corridor", "cosmic", "cottage", "cotton", "council", "counsel", "counter",
    "country", "courage", "courier", "cove", "cradle", "craft", "crater", "crawfish",
    "creature", "credible", "credit", "creek", "crescent", "crest", "cricket", "crimson",
    "crisis", "crisp", "critique", "cross", "crown", "crucial", "cruise", "crystal",
    "culprit", "culture", "cupboard", "curator", "curiosity", "curtain", "cushion", "custom",
    "cyclone", "cylinder", "dagger", "daisy", "damage", "dancer", "dandelion", "danger",
    "daring", "darkness", "darling", "database", "daughter", "dawn", "daylight", "dazzle",
    "deadline", "dealer", "debate", "debris", "decade", "december", "decide", "decimal",
    "decision", "deck", "declare", "decline", "decode", "decor", "decrease", "dedicate",
    "defender", "defense", "deficit", "define", "degree", "delay", "delegate", "delight",
    "deliver", "delta", "demand", "demise", "dentist", "depart", "depend", "deposit",
    "depth", "deputy", "derby", "derive", "desert", "design", "desire", "desktop",
    "destiny", "destroy", "detail", "detect", "develop", "device", "devote", "dialogue",
    "diamond", "diary", "diesel", "differ", "digital", "dignity", "dilemma", "dinner",
    "dinosaur", "diploma", "direct", "director", "disable", "disciple", "discover", "display",
    "distance", "district", "diver", "divide", "divine", "doctrine", "document", "dolphin",
    "domain", "donate", "doorstep", "double", "dragon", "drain", "dramatic", "drawer",
    "dream", "drift", "drill", "driver", "droplet", "drummer", "dryer", "duckling",
    "duet", "dune", "duplicate", "durable", "duration", "dynamic", "eagle", "early",
    "earnest", "earth", "easel", "eclipse", "ecology", "economy", "ecosystem", "edition",
    "educate", "effort", "elastic", "elder", "election", "electric", "element", "elephant",
    "elevate", "eligible", "elite", "elm", "embark", "embassy", "emerald", "emerge",
    "emission", "emotion", "emperor", "emphasis", "empire", "empower", "emulate", "enamel",
    "enchant", "encore", "endeavor", "endless", "endorse", "endure", "energy", "enforce",
    "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "ensemble",
    "ensure", "enter", "entire", "entity", "envelope", "envoy", "episode", "epoch",
    "equality", "equation", "equator", "equity", "era", "erosion", "error", "erupt",
    "escape", "essay", "essence", "estate", "estimate", "eternal", "ether", "ethics",
    "euphoria", "evacuate", "evaluate", "evening", "evidence", "evolve", "exact", "exalt",
    "example", "exceed", "excel", "exchange", "excite", "exclude", "execute", "exempt",
    "exercise", "exhale", "exhibit", "exile", "exist", "exotic", "expand", "expect",
    "expedition", "expert", "expire", "explain", "explore", "exponent", "export", "express",
    "extend", "exterior", "external", "extinct", "extra", "extreme", "fabric", "facade",
    "facet", "factory", "faculty", "falcon", "famine", "famous", "fantasy", "farmland",
    "fashion", "fasten", "father", "fatigue", "faucet", "feather", "feature", "february",
    "federal", "feeble", "fellow", "feline", "fence", "fender", "ferry", "festival",
    "fiction", "field", "fierce", "figure", "filing", "filter", "finalize", "finance",
    "finch", "finger", "finish", "fir", "firefly", "fireplace", "firm", "fountain",
    "fox", "fragment", "fragrance", "frame", "franchise", "frank", "freedom", "freezer",
    "freight", "frequency", "freshen", "friction", "frigate", "frost", "frontier", "fruit",
    "fuel", "fulfill", "furnace", "furniture", "galaxy", "gallery", "gamble", "garlic",
    "garnet", "gasoline", "gateway", "gather", "gauntlet", "gazelle", "gearbox", "general",
    "generate", "genius", "gentle", "genuine", "geology", "geometry", "gesture", "giant",
    "glacier", "glamour", "glance", "glider", "glimmer", "glimpse", "glisten", "global",
    "globe", "glorious", "glossary", "glow", "goblet", "goddess", "goldfish", "gondola",
    "goodwill", "gospel", "govern", "graceful", "graduate", "grain", "grammar", "grand",
    "granite", "grape", "graph", "grasp", "gravity", "grazing", "greatness", "greenhouse",
    "grenade", "grid", "grizzly", "groove", "ground", "grove", "growth", "guardian",
    "guidance", "guitar", "gull", "habitat", "halcyon", "hamlet", "hammer", "handshake",
    "harbor", "hardship", "harmony", "harvest", "haven", "hawk", "hazard", "header",
    "heading", "headline", "healing", "health", "heart", "hearth", "heater", "heaven",
    "hedgehog", "height", "heirloom", "helium", "helmet", "helper", "herald", "herb",
    "heritage", "heroic", "heron", "hibernate", "highland", "highway", "hillside", "history",
    "hobby", "holding", "holiday", "hollow", "homeland", "honesty", "honeybee", "horizon",
    "hormone", "hornet", "hospital", "hostile", "hotel", "hourglass", "hover", "hub",
    "humming", "humor", "hurricane", "hustle", "hydrant", "hydrogen", "hygiene", "iceberg",
    "icicle", "ideal", "identify", "identity", "idiom", "idle", "ignite", "ignore",
    "iguana", "illumine", "illusion", "illustrate", "image", "immense", "impact", "impart",
    "imperial", "implement", "implicit", "impose", "impress", "improve", "impulse", "inbox",
    "incident", "income", "increase", "index", "indicate", "indoor", "industry", "infinite",
    "influx", "inform", "inherit", "initial", "inject", "inland", "innovate", "input",
    "inquire", "insect", "insight", "inspect", "inspire", "install", "instant", "instinct",
    "insure", "intact", "integral", "intend", "intense", "interact", "interest", "interior",
    "interval", "intimate", "intrigue", "invent", "invest", "invite", "invoke", "iris",
    "island", "isolate", "issue", "ivory", "jacket", "jaguar", "jasmine", "javelin",
    "jazz", "jellyfish", "jewel", "jigsaw", "jockey", "journey", "jovial", "jubilee",
    "judge", "juggle", "juice", "jumbo", "junction", "jungle", "jupiter", "juror",
    "justice", "justify", "keeper", "kernel", "kettle", "keyboard", "keynote", "kickoff",
    "kinetic", "kingdom", "kinsman", "kitchen", "kite", "kitten", "knapsack", "knight",
]


def generate_random_password(
    length: int = 20,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
    min_digits: int = 1,
    min_symbols: int = 1,
) -> str:
    """Generate cryptographically secure random password with customizable constraints."""
    minimum = 4 if symbols else 3
    if not isinstance(length, int) or length < minimum:
        raise ValueError(f"password length must be at least {minimum}")
    if length > 1024:
        raise ValueError("password length must not exceed 1024")

    lowers = [c for c in string.ascii_lowercase if not (exclude_ambiguous and c in AMBIGUOUS_CHARS)]
    uppers = [c for c in string.ascii_uppercase if not (exclude_ambiguous and c in AMBIGUOUS_CHARS)]
    digits = [c for c in string.digits if not (exclude_ambiguous and c in AMBIGUOUS_CHARS)]
    sym_pool = [c for c in string.punctuation if not (exclude_ambiguous and c in AMBIGUOUS_CHARS)] if symbols else []

    chars: List[str] = [
        secrets.choice(lowers),
        secrets.choice(uppers),
    ]

    for _ in range(max(1, min_digits)):
        chars.append(secrets.choice(digits))

    if symbols and sym_pool:
        for _ in range(max(1, min_symbols)):
            chars.append(secrets.choice(sym_pool))

    full_pool = lowers + uppers + digits + (sym_pool if symbols else [])
    chars += [secrets.choice(full_pool) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(
    words: int = 5,
    sep: str = "-",
    capitalize: bool = False,
    include_number: bool = False,
) -> str:
    """Generate high-entropy passphrase using EFF wordlist."""
    if not isinstance(words, int) or words < 3:
        raise ValueError("passphrase words must be at least 3")
    if words > 32:
        raise ValueError("passphrase words must not exceed 32")

    chosen = [secrets.choice(EFF_WORDLIST) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    if include_number:
        chosen[-1] = chosen[-1] + str(secrets.randbelow(100))

    return sep.join(chosen)


def generate_candidates(
    count: int = 3,
    length: int = 20,
    symbols: bool = True,
    exclude_ambiguous: bool = True,
    words: int = 0,
    sep: str = "-",
) -> List[Tuple[str, float, str]]:
    """Generate multiple candidate secrets with their Shannon entropy and crack time."""
    from vault.ui import calculate_entropy

    candidates: List[Tuple[str, float, str]] = []
    for _ in range(max(1, min(count, 10))):
        if words > 0:
            candidate = generate_passphrase(words=words, sep=sep)
        else:
            candidate = generate_random_password(
                length=length,
                symbols=symbols,
                exclude_ambiguous=exclude_ambiguous,
            )
        ent, crack_time = calculate_entropy(candidate)
        candidates.append((candidate, ent, crack_time))
    return candidates
