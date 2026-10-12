from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import joblib
import pandas as pd
import numpy as np
import os
import json
import subprocess
import sys

from werkzeug.security import generate_password_hash, check_password_hash

from file_analyzer import analyze_network_file


# =========================================================
# FLASK CONFIGURATION
# =========================================================

app = Flask(__name__)

app.secret_key = "cyber_defence_project_secret_key_2026"


# =========================================================
# PATHS
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "model",
    "cyber_model.pkl"
)

ENCODER_PATH = os.path.join(
    BASE_DIR,
    "model",
    "attack_encoder.pkl"
)

USERS_FILE = os.path.join(
    BASE_DIR,
    "users.json"
)

TEMP_FOLDER = os.path.join(
    BASE_DIR,
    "temp_uploads"
)

LIVE_DATA_FILE = os.path.join(
    BASE_DIR,
    "live_monitor_data.json"
)


# =========================================================
# NSL-KDD COLUMNS
# =========================================================

NSL_KDD_COLUMNS = [

    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "attack",
    "difficulty"
]


MODEL_FEATURES = NSL_KDD_COLUMNS[:41]


CATEGORICAL_FEATURES = [
    "protocol_type",
    "service",
    "flag"
]


# =========================================================
# LOAD MODEL
# =========================================================

model = None

try:

    model = joblib.load(
        MODEL_PATH
    )

    print()
    print("=" * 70)
    print("ML MODEL LOADED SUCCESSFULLY")
    print("=" * 70)
    print("Model:", type(model))

except Exception as e:

    print()
    print("=" * 70)
    print("MODEL LOADING ERROR")
    print("=" * 70)
    print(repr(e))


# =========================================================
# LOAD ATTACK ENCODER
# =========================================================

attack_encoder = None

if os.path.exists(ENCODER_PATH):

    try:

        attack_encoder = joblib.load(
            ENCODER_PATH
        )

        print(
            "ATTACK ENCODER LOADED"
        )

    except Exception as e:

        print(
            "ATTACK ENCODER ERROR:",
            repr(e)
        )

else:

    print(
        "WARNING: attack_encoder.pkl not found."
    )


# =========================================================
# USER DATABASE
# =========================================================

def load_users():

    if not os.path.exists(USERS_FILE):

        default_users = {

            "admin":
            generate_password_hash(
                "admin123"
            )

        }

        with open(
            USERS_FILE,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                default_users,
                f,
                indent=4
            )

        return default_users

    try:

        with open(
            USERS_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            return json.load(f)

    except Exception as e:

        print(
            "USER DATABASE ERROR:",
            repr(e)
        )

        return {}


users = load_users()


# =========================================================
# ATTACK RESPONSE
# =========================================================

attack_response = {

    "DoS": {

        "severity": "High",

        "action":
        "Rate limiting and suspicious traffic monitoring",

        "solution":
        "Monitor high-volume traffic, apply rate limiting, "
        "block suspicious sources and investigate abnormal traffic."

    },

    "Probe": {

        "severity": "Medium",

        "action":
        "Port scanning detection and source monitoring",

        "solution":
        "Monitor repeated connection attempts, detect port scanning "
        "and investigate suspicious sources."

    },

    "R2L": {

        "severity": "High",

        "action":
        "Authentication and access-control monitoring",

        "solution":
        "Strengthen authentication, monitor failed login attempts "
        "and restrict unauthorized access."

    },

    "U2R": {

        "severity": "Critical",

        "action":
        "Privilege monitoring",

        "solution":
        "Monitor privilege escalation, restrict administrator access "
        "and investigate suspicious privileged activity."

    },

    "Normal": {

        "severity": "Low",

        "action":
        "Continue monitoring",

        "solution":
        "No immediate attack response required. "
        "Continue normal network monitoring."

    }
}


# =========================================================
# FEATURE ALIASES
# =========================================================

FEATURE_ALIASES = {

    "duration":
    ["duration", "flow_duration", "flow_dur", "dur"],

    "protocol_type":
    ["protocol_type", "protocol", "proto"],

    "service":
    ["service", "application", "service_name", "app"],

    "flag":
    ["flag", "flags", "tcp_flags", "tcp_flag"],

    "src_bytes":
    ["src_bytes", "source_bytes", "bytes_sent"],

    "dst_bytes":
    ["dst_bytes", "destination_bytes", "bytes_received"],

    "land":
    ["land"],

    "wrong_fragment":
    ["wrong_fragment", "fragment"],

    "urgent":
    ["urgent", "urgent_packets"],

    "hot":
    ["hot"],

    "num_failed_logins":
    ["num_failed_logins", "failed_logins", "failed_login"],

    "logged_in":
    ["logged_in", "login_success"],

    "num_compromised":
    ["num_compromised", "compromised"],

    "root_shell":
    ["root_shell"],

    "su_attempted":
    ["su_attempted", "su_attempt"],

    "num_root":
    ["num_root", "root_count"],

    "num_file_creations":
    ["num_file_creations", "file_creations"],

    "num_shells":
    ["num_shells", "shells"],

    "num_access_files":
    ["num_access_files", "access_files"],

    "num_outbound_cmds":
    ["num_outbound_cmds", "outbound_commands"],

    "is_host_login":
    ["is_host_login", "host_login"],

    "is_guest_login":
    ["is_guest_login", "guest_login"],

    "count":
    ["count", "connection_count", "flow_count"],

    "srv_count":
    ["srv_count", "service_count"],

    "serror_rate":
    ["serror_rate", "syn_error_rate"],

    "srv_serror_rate":
    ["srv_serror_rate", "service_serror_rate"],

    "rerror_rate":
    ["rerror_rate", "reject_error_rate"],

    "srv_rerror_rate":
    ["srv_rerror_rate", "service_rerror_rate"],

    "same_srv_rate":
    ["same_srv_rate", "same_service_rate"],

    "diff_srv_rate":
    ["diff_srv_rate", "different_service_rate"],

    "srv_diff_host_rate":
    ["srv_diff_host_rate", "service_diff_host_rate"],

    "dst_host_count":
    ["dst_host_count", "destination_host_count"],

    "dst_host_srv_count":
    ["dst_host_srv_count", "destination_host_service_count"],

    "dst_host_same_srv_rate":
    ["dst_host_same_srv_rate", "destination_host_same_service_rate"],

    "dst_host_diff_srv_rate":
    ["dst_host_diff_srv_rate", "destination_host_diff_service_rate"],

    "dst_host_same_src_port_rate":
    ["dst_host_same_src_port_rate", "same_source_port_rate"],

    "dst_host_srv_diff_host_rate":
    ["dst_host_srv_diff_host_rate", "service_diff_host_rate"],

    "dst_host_serror_rate":
    ["dst_host_serror_rate"],

    "dst_host_srv_serror_rate":
    ["dst_host_srv_serror_rate"],

    "dst_host_rerror_rate":
    ["dst_host_rerror_rate"],

    "dst_host_srv_rerror_rate":
    ["dst_host_srv_rerror_rate"]
}


# =========================================================
# NORMALIZE COLUMN
# =========================================================

def normalize_column(name):

    name = str(
        name
    ).strip().lower()

    name = name.replace(
        "-",
        "_"
    )

    name = name.replace(
        " ",
        "_"
    )

    return name


# =========================================================
# DETECT FEATURES
# =========================================================

def detect_features(data):

    normalized = {}

    for column in data.columns:

        normalized[
            normalize_column(column)
        ] = column

    matched = {}

    for standard, aliases in FEATURE_ALIASES.items():

        for alias in aliases:

            alias = normalize_column(
                alias
            )

            if alias in normalized:

                matched[
                    standard
                ] = normalized[
                    alias
                ]

                break

    return matched


# =========================================================
# PREPARE MODEL INPUT
# =========================================================

def prepare_model_input(data):

    matched = detect_features(
        data
    )

    X = pd.DataFrame(
        index=data.index
    )

    matched_count = 0
    default_count = 0

    for feature in MODEL_FEATURES:

        if feature in matched:

            original_column = matched[
                feature
            ]

            values = data[
                original_column
            ].copy()

            matched_count += 1

            if feature in CATEGORICAL_FEATURES:

                values = (
                    values
                    .astype(str)
                    .str.strip()
                    .str.lower()
                )

                values = values.replace(
                    [
                        "",
                        "nan",
                        "none",
                        "null"
                    ],
                    "unknown"
                )

                X[feature] = values

            else:

                values = pd.to_numeric(
                    values,
                    errors="coerce"
                )

                values = values.replace(
                    [
                        np.inf,
                        -np.inf
                    ],
                    np.nan
                )

                values = values.fillna(
                    0
                )

                X[feature] = values

        else:

            default_count += 1

            if feature in CATEGORICAL_FEATURES:

                X[feature] = "unknown"

            else:

                X[feature] = 0

    X = X[
        MODEL_FEATURES
    ]

    return (
        X,
        matched_count,
        default_count
    )


# =========================================================
# NORMALIZE ATTACK LABEL
# =========================================================

def normalize_attack_label(label):

    label = str(
        label
    ).strip()

    mapping = {

        "normal": "Normal",
        "normal.": "Normal",

        "dos": "DoS",
        "dos.": "DoS",

        "probe": "Probe",
        "probe.": "Probe",

        "r2l": "R2L",
        "r2l.": "R2L",

        "u2r": "U2R",
        "u2r.": "U2R"
    }

    return mapping.get(
        label.lower(),
        label
    )


# =========================================================
# CONVERT PREDICTIONS
# =========================================================

def convert_predictions(predictions):

    predictions = np.asarray(
        predictions
    )

    if attack_encoder is not None:

        try:

            labels = attack_encoder.inverse_transform(
                predictions
            )

            return [
                normalize_attack_label(x)
                for x in labels
            ]

        except Exception as e:

            print(
                "Encoder conversion failed:",
                repr(e)
            )

    try:

        classifier = None

        if hasattr(
            model,
            "named_steps"
        ):

            steps = list(
                model.named_steps.values()
            )

            if steps:

                classifier = steps[-1]

        if (
            classifier is not None
            and
            hasattr(
                classifier,
                "classes_"
            )
        ):

            labels = []

            classes = classifier.classes_

            for value in predictions:

                try:

                    index = int(value)

                    if (
                        index >= 0
                        and
                        index < len(classes)
                    ):

                        labels.append(
                            normalize_attack_label(
                                classes[index]
                            )
                        )

                    else:

                        labels.append(
                            normalize_attack_label(
                                value
                            )
                        )

                except:

                    labels.append(
                        normalize_attack_label(
                            value
                        )
                    )

            return labels

    except Exception as e:

        print(
            "Class conversion error:",
            repr(e)
        )

    return [
        normalize_attack_label(x)
        for x in predictions
    ]


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if "username" not in session:

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    error = ""

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        valid = False

        if username in users:

            try:

                valid = check_password_hash(
                    users[username],
                    password
                )

            except Exception:

                valid = False

        if valid:

            session["username"] = username

            return redirect(
                url_for("home")
            )

        error = "Invalid username or password."

    return render_template(
        "login.html",
        error=error
    )


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    error = ""

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username:

            error = "Username is required."

        elif not password:

            error = "Password is required."

        elif len(password) < 4:

            error = (
                "Password must contain at least 4 characters."
            )

        elif username in users:

            error = "Username already exists."

        else:

            users[username] = generate_password_hash(
                password
            )

            with open(
                USERS_FILE,
                "w",
                encoding="utf-8"
            ) as f:

                json.dump(
                    users,
                    f,
                    indent=4
                )

            return redirect(
                url_for("login")
            )

    return render_template(
        "register.html",
        error=error
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# LIVE MONITOR PAGE
# =========================================================

@app.route("/live-monitor")
def live_monitor():

    if "username" not in session:

        return redirect(
            url_for("login")
        )

    return render_template(
        "live_monitor.html"
    )


# =========================================================
# START LIVE MONITOR
# =========================================================

@app.route("/start-live-monitor")
def start_live_monitor():

    if "username" not in session:

        return redirect(
            url_for("login")
        )

    try:

        monitor_path = os.path.join(
            BASE_DIR,
            "live_moniter.py"
        )

        if not os.path.exists(
            monitor_path
        ):

            return f"""
            <h2>Live Monitor Error</h2>
            <p>live_moniter.py not found.</p>
            <a href="/live-monitor">
            Go Back
            </a>
            """

        subprocess.Popen(
            [
                sys.executable,
                monitor_path
            ],
            cwd=BASE_DIR,
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )

        return redirect(
            url_for("live_monitor")
        )

    except Exception as e:

        return f"""
        <h2>Live Monitor Error</h2>

        <p>
        {str(e)}
        </p>

        <a href="/live-monitor">
        Go Back
        </a>
        """


# =========================================================
# LIVE DATA API
# =========================================================

@app.route("/live-data")
def live_data():

    if "username" not in session:

        return jsonify({
            "status": "unauthorized"
        }), 401

    default_data = {

        "status": "ready",

        "monitoring": False,

        "total_packets": 0,

        "normal_packets": 0,

        "attack_packets": 0,

        "alerts": 0,

        "last_packet": None,

        "recent_packets": []

    }

    if not os.path.exists(
        LIVE_DATA_FILE
    ):

        return jsonify(
            default_data
        )

    try:

        with open(
            LIVE_DATA_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

        return jsonify(
            data
        )

    except Exception as e:

        print(
            "Live data API error:",
            repr(e)
        )

        return jsonify(
            default_data
        )


# =========================================================
# PREDICTION
# =========================================================

@app.route(
    "/prediction",
    methods=["GET", "POST"]
)
def prediction():

    if "username" not in session:

        return redirect(
            url_for("login")
        )

    if request.method == "GET":

        return render_template(
            "prediction.html",
            file_info="",
            first10="",
            summary="",
            labels=[],
            values=[],
            total_records=0,
            total_normal=0,
            total_attacks=0,
            total_attack_types=0,
            response_details=[],
            conversion_info=""
        )

    uploaded_file = request.files.get(
        "dataset_file"
    )

    if (
        uploaded_file is None
        or
        not uploaded_file.filename
    ):

        return render_template(
            "prediction.html",
            file_info="❌ Please select a dataset file.",
            first10="",
            summary="",
            labels=[],
            values=[],
            total_records=0,
            total_normal=0,
            total_attacks=0,
            total_attack_types=0,
            response_details=[],
            conversion_info=""
        )

    safe_filename = os.path.basename(
        uploaded_file.filename
    )

    extension = os.path.splitext(
        safe_filename
    )[1].lower()

    if extension not in [".csv", ".txt"]:

        return render_template(
            "prediction.html",
            file_info="❌ Only CSV and TXT files are supported.",
            first10="",
            summary="",
            labels=[],
            values=[],
            total_records=0,
            total_normal=0,
            total_attacks=0,
            total_attack_types=0,
            response_details=[],
            conversion_info=""
        )

    os.makedirs(
        TEMP_FOLDER,
        exist_ok=True
    )

    temp_path = os.path.join(
        TEMP_FOLDER,
        safe_filename
    )

    uploaded_file.save(
        temp_path
    )

    try:

        analyze_network_file(
            temp_path
        )

    except Exception as e:

        print(
            "Analyzer Error:",
            repr(e)
        )

    try:

        if extension == ".txt":

            raw = pd.read_csv(
                temp_path,
                header=None,
                sep=","
            )

            if raw.shape[1] == 43:

                data = pd.read_csv(
                    temp_path,
                    header=None,
                    names=NSL_KDD_COLUMNS,
                    sep=","
                )

            else:

                data = pd.read_csv(
                    temp_path,
                    sep=","
                )

        else:

            data = pd.read_csv(
                temp_path
            )

    except Exception as e:

        try:
            os.remove(temp_path)
        except:
            pass

        return render_template(
            "prediction.html",
            file_info="❌ Unable to read the uploaded dataset.",
            first10="",
            summary="",
            labels=[],
            values=[],
            total_records=0,
            total_normal=0,
            total_attacks=0,
            total_attack_types=0,
            response_details=[],
            conversion_info=""
        )

    data = data.dropna(
        how="all"
    ).reset_index(
        drop=True
    )

    if len(data) == 0:

        return render_template(
            "prediction.html",
            file_info="❌ Dataset contains no usable records.",
            first10="",
            summary="",
            labels=[],
            values=[],
            total_records=0,
            total_normal=0,
            total_attacks=0,
            total_attack_types=0,
            response_details=[],
            conversion_info=""
        )

    try:

        X, matched_count, default_count = prepare_model_input(
            data
        )

    except Exception as e:

        return render_template(
            "prediction.html",
            file_info="❌ Feature preparation failed.",
            first10="",
            summary="",
            labels=[],
            values=[],
            total_records=0,
            total_normal=0,
            total_attacks=0,
            total_attack_types=0,
            response_details=[],
            conversion_info=str(e)
        )

    if model is None:

        return render_template(
            "prediction.html",
            file_info="❌ ML model is not loaded.",
            first10="",
            summary="",
            labels=[],
            values=[],
            total_records=len(X),
            total_normal=0,
            total_attacks=0,
            total_attack_types=0,
            response_details=[],
            conversion_info=""
        )

    try:

        predictions = model.predict(
            X
        )

    except Exception as e:

        return render_template(
            "prediction.html",
            file_info="❌ Prediction failed: " + str(e),
            first10="",
            summary="",
            labels=[],
            values=[],
            total_records=len(X),
            total_normal=0,
            total_attacks=0,
            total_attack_types=0,
            response_details=[],
            conversion_info=""
        )

    predicted_labels = convert_predictions(
        predictions
    )

    attack_summary = pd.Series(
        predicted_labels
    ).value_counts()

    labels = attack_summary.index.tolist()

    values = attack_summary.values.tolist()

    total_records = len(
        predicted_labels
    )

    total_normal = int(
        attack_summary.get(
            "Normal",
            0
        )
    )

    total_attacks = (
        total_records
        -
        total_normal
    )

    total_attack_types = len(
        attack_summary
    )

    first10 = "<br>".join(
        str(x)
        for x in predicted_labels[:10]
    )

    summary = "<br>".join(
        f"{attack} : {int(count)}"
        for attack, count
        in attack_summary.items()
    )

    response_details = []

    for attack, count in attack_summary.items():

        if attack in attack_response:

            response_details.append({

                "category": attack,

                "count": int(count),

                "severity":
                attack_response[attack]["severity"],

                "action":
                attack_response[attack]["action"],

                "solution":
                attack_response[attack]["solution"]

            })

    file_info = (
        f"File: {safe_filename} | "
        f"Rows: {len(data)} | "
        f"Columns: {len(data.columns)}"
    )

    conversion_info = (
        f"Model Features: {len(X.columns)} | "
        f"Matched: {matched_count} | "
        f"Generated Defaults: {default_count}"
    )

    try:
        os.remove(temp_path)
    except:
        pass

    return render_template(

        "prediction.html",

        file_info=file_info,

        first10=first10,

        summary=summary,

        labels=labels,

        values=values,

        total_records=total_records,

        total_normal=total_normal,

        total_attacks=total_attacks,

        total_attack_types=total_attack_types,

        response_details=response_details,

        conversion_info=conversion_info
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )