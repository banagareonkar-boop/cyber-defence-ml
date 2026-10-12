import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder

# Load Model
model = joblib.load("model/cyber_model.pkl")

# Column Names
columns = [
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root",
"num_file_creations","num_shells","num_access_files","num_outbound_cmds",
"is_host_login","is_guest_login","count","srv_count","serror_rate",
"srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
"diff_srv_rate","srv_diff_host_rate","dst_host_count",
"dst_host_srv_count","dst_host_same_srv_rate",
"dst_host_diff_srv_rate","dst_host_same_src_port_rate",
"dst_host_srv_diff_host_rate","dst_host_serror_rate",
"dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate","attack","difficulty"
]

# Load Dataset
data = pd.read_csv("dataset/KDDTrain+.txt", names=columns)

# Encoding
encoder = LabelEncoder()
data["protocol_type"] = encoder.fit_transform(data["protocol_type"])
data["service"] = encoder.fit_transform(data["service"])
data["flag"] = encoder.fit_transform(data["flag"])
data["attack"] = encoder.fit_transform(data["attack"])

# Features
X = data.drop("attack", axis=1)

# Prediction
prediction = model.predict(X.head(10))

print("Prediction Result")
print(prediction)