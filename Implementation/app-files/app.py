from json import encoder
from altair.vegalite.v4.api import value
from keras import layers
import streamlit as st
from sklearn.preprocessing import LabelEncoder
import numpy as np 
import os
import pandas as pd
import sklearn
import time
import subprocess

import matplotlib.pyplot as plt
from sklearn import datasets
from sklearn.model_selection import train_test_split
from streamlit_echarts import st_echarts

from sklearn.decomposition import PCA
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score
import plotly.express as px
import shap
import threading
from collections import defaultdict
from streamlit_autorefresh import st_autorefresh

try:
    from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, get_if_list  # type: ignore
except Exception:
    AsyncSniffer = None
    IP = IPv6 = TCP = UDP = None
    get_if_list = None

@st.cache_resource
def get_live_store():
    """
    Persistent, thread-safe store for live capture across Streamlit reruns.
    Avoid mutating st.session_state from background sniffing threads.
    """
    lock = threading.Lock()
    flows = defaultdict(lambda: {"first_ts": None, "last_ts": None, "packets": 0, "bytes": 0})
    totals = {"packets": 0, "bytes": 0, "last_ts": None}
    return lock, flows, totals

FLOW_BASE_COLS = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packets", "bytes", "duration_s"]

def _is_flow_capture_df(df: pd.DataFrame) -> bool:
    cols = [c.strip() for c in df.columns.astype(str).tolist()]
    return all(c in cols for c in FLOW_BASE_COLS)

def _safe_div(n: pd.Series, d: pd.Series, eps: float = 1e-9) -> pd.Series:
    d2 = d.astype(float).copy()
    d2 = d2.where(d2.abs() > eps, eps)
    return n.astype(float) / d2

def build_flow_features(
    df: pd.DataFrame,
    *,
    fit: bool,
    drop_ip: bool,
    label_col: str | None,
):
    """
    Build the exact same flow-level feature matrix for both:
    - offline training datasets derived from live capture schema
    - live captured flows_df

    Returns: X (DataFrame), y (Series|None)
    """
    df2 = df.copy()

    # Normalize expected columns (best-effort)
    for c in ["src_port", "dst_port", "packets", "bytes", "duration_s"]:
        if c in df2.columns:
            df2[c] = pd.to_numeric(df2[c], errors="coerce").fillna(0)

    if "protocol" in df2.columns:
        df2["protocol"] = df2["protocol"].astype(str).str.lower().fillna("other")

    # Derived, alignment-friendly features
    if "bytes" in df2.columns and "packets" in df2.columns:
        df2["bytes_per_packet"] = _safe_div(df2["bytes"], df2["packets"].clip(lower=1))
    if "packets" in df2.columns and "duration_s" in df2.columns:
        df2["pps"] = _safe_div(df2["packets"], df2["duration_s"])
    if "bytes" in df2.columns and "duration_s" in df2.columns:
        df2["bps"] = _safe_div(df2["bytes"], df2["duration_s"])
    if "bytes" in df2.columns:
        df2["log_bytes"] = np.log1p(df2["bytes"].astype(float).clip(lower=0))

    y = None
    if label_col and label_col in df2.columns:
        y = df2[label_col].copy()

    drop_cols = []
    if drop_ip:
        for c in ["src_ip", "dst_ip"]:
            if c in df2.columns:
                drop_cols.append(c)
    if label_col and label_col in df2.columns:
        drop_cols.append(label_col)

    X = df2.drop(columns=drop_cols, errors="ignore").copy()

    # Encode categorical columns deterministically
    Dataframe.encoders = getattr(Dataframe, "encoders", {})
    num_cols = X._get_numeric_data().columns
    cate_cols = list(set(X.columns) - set(num_cols))
    for item in cate_cols:
        le = Dataframe.encoders.get(item)
        if fit or le is None:
            le = LabelEncoder()
            X[item] = le.fit_transform(X[item].astype(str))
            Dataframe.encoders[item] = le
        else:
            # Handle unseen categories at inference: map unknowns to -1
            known = set(getattr(le, "classes_", []))
            X[item] = X[item].astype(str).apply(lambda v: le.transform([v])[0] if v in known else -1)

    return X, y

st.title('Anomaly-Based IDS Workbench System')

st.write("""
#
""")



hide_streamlit_style = """
            <style>
            footer {visibility: hidden;}
            </style>
            """
st.markdown(hide_streamlit_style, unsafe_allow_html=True)




#Defining Python Global Class Design Pattern here
class Dataframe:
    #pass
    ratio=0.33

class MetricsReport:
    report = []

#Defining Python Strategy Design Pattern here
class StrategyClass:
    def __init__(self, func=None):
        if func:
             self.execute = func

    def execute(self):
        print("No Execution Passed to Strategy Class")


class DataExploration:
    #Defining visualization plot here
    def plot_column( col ):
        if Dataframe.df[col].dtype == 'object':
            encoder=LabelEncoder()
            Dataframe.df[col] = encoder.fit_transform(Dataframe.df[col])
        fig, ax = plt.subplots()
        Dataframe.df.hist(
            bins=8,
            column= col ,
            grid=False,
            figsize=(8, 8),
            color="#86bf91",
            zorder=2,
            rwidth=0.9,
            ax=ax,
        )
        st.write(fig)

    #@st.cache(suppress_st_warning=True)
    def write_statistics(statistics, visualizaitons):
        if 'Dataset Shape' in statistics:
            st.write('Shape of Dataset:', Dataframe.df.shape)
        if 'Number of Classes' in statistics:
            st.write('Number of Classes:', len(np.unique(Dataframe.y)))
        if 'Dataset Head' in statistics:
            st.write('Dataset Head:', Dataframe.df.head(5))
        if 'Describe Features' in statistics:
            st.write('Feature Description:', Dataframe.df.describe())
        if 'View Packet Types' in statistics:
            st.write('Packet Types:', np.unique(Dataframe.y))
        if 'Scatter Plots' in statistics:
            st.subheader("Scatter Plot:")
            plot_dim = st.selectbox("Select plot dimensionality", ('2D Plot', '3D Plot'))
            with st.form('Scatter Plot Form'):
                max_rows = min(200, len(Dataframe.df.index))
                num_samples = st.slider(label="Select number of random samples", min_value=1, max_value=max_rows)
                sampling_technique = st.radio('Sampling Technique:', ['Random Sampling', 'Equal Distribution Sampling'])
                if sampling_technique == 'Random Sampling':
                    sample_df = Dataframe.df.sample(num_samples)
                else:
                    sample_df = Dataframe.df.groupby(Dataframe.df.columns[len(Dataframe.df.columns)-1]).apply(lambda x: x.sample(num_samples, replace=True))

                if plot_dim == '2D Plot':
                    feature_x = st.selectbox('Select X-Axis Feature', (Dataframe.df.columns))
                    feature_y = st.selectbox('Select Y-Axis Feature', (Dataframe.df.columns))
                    if(feature_x and feature_y):
                        fig = px.scatter(sample_df, x= feature_x, y = feature_y, color=sample_df.columns[len(sample_df.columns)-1])
                        st.plotly_chart(fig)
                if plot_dim == '3D Plot':
                    feature_x = st.selectbox('Select X-Axis Feature', (Dataframe.df.columns))
                    feature_y = st.selectbox('Select Y-Axis Feature', (Dataframe.df.columns))
                    feature_z = st.selectbox('Select Z-Axis Feature', (Dataframe.df.columns))
                    if(feature_x and feature_y):
                        fig = px.scatter_3d(sample_df, feature_x, feature_y, feature_z, color = sample_df.columns[len(sample_df.columns)-1])
                        st.plotly_chart(fig)

                scatter_submit = st.form_submit_button('Apply Selected Options')

            

        if visualizaitons:
            DataExploration.write_visualizations(visualizaitons)

    #@st.cache(suppress_st_warning=True)
    def write_visualizations(visualizaitons):
        for column in visualizaitons:
            DataExploration.plot_column(col=column)

    
    def populate_statistics():
        st.sidebar.header('Data Exploration')
        #Print statistics and visualizations sidebar items
        statistics=False
        visualizaitons=False
        with st.sidebar.form('Statistics Form'):
            statistics = st.multiselect(
                'Select Desired Statistics',
                ('Dataset Head', 'Dataset Shape', 'Number of Classes', 'Describe Features', 'View Packet Types', 'Scatter Plots', 'Plot Feature Visualizations')
            )
            statistics_submit = st.form_submit_button('Show Selected Options')

        if 'Plot Feature Visualizations' in statistics:
            with st.sidebar.form('Visualizations Form'):
                visualizaitons = st.multiselect(
                    'Select Desired Visualizations',
                    (Dataframe.df.columns)
                )
                visualizations_submit = st.form_submit_button('Show Selected Options')

        if statistics:
            DataExploration.write_statistics(statistics, visualizaitons)


class DataInput:
    def read_data():
        #Reading uploaded dataset csv file here
        Dataframe.df = pd.read_csv(uploaded_file)


        #Replace NaN/Infinite values with 0
        Dataframe.df = Dataframe.df.fillna(0)
        Dataframe.df = Dataframe.df.replace([np.inf, -np.inf], 0)

        st.sidebar.header("Dataset Mode")
        auto_flow = _is_flow_capture_df(Dataframe.df)
        flow_mode = st.sidebar.checkbox(
            "Flow-feature aligned mode (recommended for live capture alignment)",
            value=auto_flow,
            help="Train on the same flow-level features produced by live capture (packets/bytes/duration/etc.).",
        )
        Dataframe.flow_mode = bool(flow_mode)
        Dataframe.flow_drop_ip = st.sidebar.checkbox(
            "Drop IP address features (recommended)",
            value=True,
            help="Avoid overfitting to specific IPs; keeps ports/protocol/counters only.",
        )

        if Dataframe.flow_mode:
            if not _is_flow_capture_df(Dataframe.df):
                st.warning(
                    "Flow-feature mode expects the live-capture schema columns: "
                    f"{', '.join(FLOW_BASE_COLS)}. "
                    "Upload a flow CSV (exported from live capture) with an added label column."
                )

            # Choose label column for flow datasets
            candidate_labels = [c for c in Dataframe.df.columns if str(c).lower() in ("label", "class", "target", "y")]
            default_label = candidate_labels[0] if candidate_labels else str(Dataframe.df.columns[-1])
            label_col = st.sidebar.selectbox("Label column", options=list(Dataframe.df.columns), index=list(Dataframe.df.columns).index(default_label))

            Dataframe.X_raw, Dataframe.y = build_flow_features(
                Dataframe.df,
                fit=True,
                drop_ip=Dataframe.flow_drop_ip,
                label_col=str(label_col),
            )
            Dataframe.X = Dataframe.X_raw.copy()
        else:
            #Splitting x & y dataframes here
            # Treat last column as the classification label (1-D)
            Dataframe.y = Dataframe.df.iloc[:, -1].copy()
            Dataframe.X_raw = Dataframe.df.iloc[: , :-1].copy()
            Dataframe.X = Dataframe.X_raw.copy()
            Dataframe.encoders = {}

            #Label encoding categorical features here
            num_cols = Dataframe.X._get_numeric_data().columns
            cate_cols = list(set(Dataframe.X.columns)-set(num_cols))
            for item in cate_cols:
                le = LabelEncoder()
                Dataframe.X[item] = le.fit_transform(Dataframe.X[item].astype(str))
                Dataframe.encoders[item] = le

        try:
            Dataframe.normal_label = str(pd.Series(Dataframe.y).mode(dropna=True)[0])
        except Exception:
            Dataframe.normal_label = None


        #Displaying dataset statistics and visualizaitons here
        strategy = StrategyClass(DataExploration.populate_statistics)
        strategy.execute()
        strategy = StrategyClass(Preprocessor.populate_preprocessors)
        strategy.execute()


class Preprocessor:
    def populate_preprocessors():
        st.sidebar.header('Preprocessing')

        #Drop null values here:
        drop_nulls_btn = st.sidebar.checkbox('Drop Rows with Null Values')
        if drop_nulls_btn:
            Dataframe.df = Dataframe.df.dropna(axis=0)
        
        #Print preprocessing sidebar items
        scaling_btn = st.sidebar.checkbox('Apply Logarithmic Scaling')
        if scaling_btn:
            # Note: this is MinMax scaling (not log scaling)
            sc = MinMaxScaler()
            Dataframe.X[Dataframe.X.columns] = sc.fit_transform(Dataframe.X)
            st.session_state.trained_scaler = sc
        else:
            st.session_state.trained_scaler = None

        ratio_btn = st.sidebar.selectbox('Select Custom/Default Test-Train Ratio',('Default', 'Custom'))
        if ratio_btn == 'Default':
            Dataframe.ratio = 0.33
        if ratio_btn == 'Custom':
            Dataframe.ratio = st.sidebar.number_input('ratio', min_value=0.01, max_value=0.99)
        
        
class Classifier:
    #Defining dynamic parameter generation here
    def add_parameters(clf_name):
        params = dict()
        if clf_name == 'SVM':
            with st.sidebar.form('SVM Form'):
                C = st.slider('C', 0.01, 10.0)
                params['C'] = C
                kernel = st.selectbox('Select kernel',('rbf', 'linear', 'poly', 'sigmoid', 'precomputed'))
                params['kernel'] = kernel
                degree = st.selectbox('Select Custom/Default degree',('Default', 'Custom'))
                if degree == 'Default':
                    params['degree'] = 3
                if degree == 'Custom':
                    degree = st.number_input('degree', min_value=1, max_value=99999999)
                    params['degree'] = degree
                probability = st.checkbox('Enable probability estimates (uses 5-fold cross-validation)')
                if probability:
                    params['probability'] = True
                else:
                    params['probability'] = False

                svm_submit = st.form_submit_button('Apply Selected Options')

        if clf_name == 'KNN':
            with st.sidebar.form('KNN Form'):
                K = st.slider('K', 1, 15)
                params['K'] = K
                algorithm = st.selectbox('Select algorithm',('auto', 'ball_tree', 'kd_tree', 'brute'))
                params['algorithm'] = algorithm
                p = st.selectbox('Select Custom/Default Power (p)',('Default', 'Custom'))
                if p == 'Default':
                    params['p'] = 2
                if p == 'Custom':
                    p = st.number_input('p', min_value=1, max_value=99999999)
                    params['p'] = p
                n_jobs = st.selectbox('Select Custom/Default n_jobs (Parallel Jobs)',('Default', 'Custom'))
                if n_jobs == 'Default':
                    params['n_jobs'] = None
                if n_jobs == 'Custom':
                    n_jobs = st.number_input('n_jobs', min_value=-1, max_value=99999999)
                    params['n_jobs'] = n_jobs

                knn_submit = st.form_submit_button('Apply Selected Options')
            

        if clf_name == 'Random Forest':
            with st.sidebar.form('RF Form'):
                max_depth = st.slider('max_depth', 2, 15)
                params['max_depth'] = max_depth
                n_estimators = st.slider('n_estimators', 1, 100)
                params['n_estimators'] = n_estimators
                min_samples_split = st.selectbox('Select Custom/Default min_samples_split',('Default', 'Custom'))
                if min_samples_split == 'Default':
                    params['min_samples_split'] = 2
                if min_samples_split == 'Custom':
                    min_samples_split = st.number_input('min_samples_split', min_value=2, max_value=99999999)
                    params['min_samples_split'] = min_samples_split
                n_jobs = st.selectbox('Select Custom/Default n_jobs (Parallel Jobs)',('Default', 'Custom'))
                if n_jobs == 'Default':
                    params['n_jobs'] = None
                if n_jobs == 'Custom':
                    n_jobs = st.number_input('n_jobs', min_value=-1, max_value=99999999)
                    params['n_jobs'] = n_jobs
                criterion = st.selectbox('Select criterion',('gini', 'entropy'))
                params['criterion'] = criterion
                
                rf_submit = st.form_submit_button('Apply Selected Options')

        if clf_name == 'Decision Tree':
            with st.sidebar.form('DT Form'):
                criterion = st.selectbox('Select criterion',('gini', 'entropy'))
                params['criterion'] = criterion
                splitter = st.selectbox('Select splitter',('best', 'random'))
                params['splitter'] = splitter
                depth_type = st.selectbox('Select Custom/Default Tree Depth',('Default', 'Custom'))
                if depth_type == 'Default':
                    params['max_depth'] = None
                if depth_type == 'Custom':
                    max_depth = st.slider('max_depth', 2, 15)
                    params['max_depth'] = max_depth
                min_samples_split = st.selectbox('Select Custom/Default min_samples_split',('Default', 'Custom'))
                if min_samples_split == 'Default':
                    params['min_samples_split'] = 2
                if min_samples_split == 'Custom':
                    min_samples_split = st.number_input('min_samples_split', min_value=2, max_value=99999999)
                    params['min_samples_split'] = min_samples_split
                min_samples_leaf = st.selectbox('Select Custom/Default min_samples_leaf',('Default', 'Custom'))
                if min_samples_leaf == 'Default':
                    params['min_samples_leaf'] = 1
                if min_samples_leaf == 'Custom':
                    min_samples_leaf = st.number_input('min_samples_leaf', min_value=1, max_value=99999999)
                    params['min_samples_leaf'] = min_samples_leaf
                
                dt_submit = st.form_submit_button('Apply Selected Options')
            

        if clf_name == 'Logistic Regression':
            with st.sidebar.form('LR Form'):
                max_iter = st.selectbox('Select Custom/Default Iterations Number',('Default', 'Custom'))
                if max_iter == 'Default':
                    params['max_iter'] = 100
                if max_iter == 'Custom':
                    max_iter = st.number_input('max_iter', min_value=1, max_value=999999999999999)
                    params['max_iter'] = max_iter
                solver = st.selectbox('Select Solver',('lbfgs', 'newton-cg', 'liblinear', 'sag', 'saga'))
                params['solver'] = solver
                penalty = st.selectbox('Select penalty',('l2', 'l1', 'elasticnet', 'none'))
                params['penalty'] = penalty
                dual = st.checkbox('Enable Dual formulation')
                if dual:
                    params['dual'] = True
                else:
                    params['dual'] = False
                n_jobs = st.selectbox('Select Custom/Default n_jobs (Parallel Jobs)',('Default', 'Custom'))
                if n_jobs == 'Default':
                    params['n_jobs'] = None
                if n_jobs == 'Custom':
                    n_jobs = st.number_input('n_jobs', min_value=-1, max_value=99999999)
                    params['n_jobs'] = n_jobs

                LR_submit = st.form_submit_button('Apply Selected Options')

        if clf_name == 'Gradient Boosting Classifier':
            with st.sidebar.form('GBC Form'):
                n_estimators = st.selectbox('Select Custom/Default No. of Estimators',('Default', 'Custom'))
                if n_estimators == 'Default':
                    params['n_estimators'] = 100
                if n_estimators == 'Custom':
                    n_estimators = st.number_input('n_estimators', min_value=1, max_value=999999999999999)
                    params['n_estimators'] = n_estimators
                loss = st.selectbox('Loss Function',('deviance', 'exponential'))
                params['loss'] = loss
                max_depth = st.selectbox('Select Custom/Default max_depth',('Default', 'Custom'))
                if max_depth == 'Default':
                    params['max_depth'] = 3
                if max_depth == 'Custom':
                    max_depth = st.number_input('max_depth', min_value=1, max_value=999999999999)
                    params['max_depth'] = max_depth

                GBC_submit = st.form_submit_button('Apply Selected Options')

        if clf_name == 'LSTM':
            st.write(" ")

        if clf_name == 'Neural Networks':
            layer_no = st.sidebar.number_input("number of hidden layers", 1, 5, 1)
            with st.sidebar.form('NN Form'):
                layers = []
                for i in range(layer_no):
                    n_neurons = st.number_input(
                        f"Number of neurons at layer {i+1}", 2, 200, 100, 25
                    )
                    layers.append(n_neurons)
                layers = tuple(layers)
                params = {"hidden_layer_sizes": layers}

                NN_submit = st.form_submit_button('Apply Selected Options')

        return params


    #Defining prediction & accuracy metrics function here
    def get_prediction():
            if st.button('Classify'):
                if uploaded_file is None:
                    st.error("Please upload a packet dataset before performing a classification task")
                    return
                st.write('Train to Test Ratio = ', Dataframe.ratio)
                
                # Validate label column looks like classification labels (not continuous regression targets)
                try:
                    y_series = pd.Series(Dataframe.y)
                    unique_count = int(y_series.nunique(dropna=True))
                    n_rows = int(len(y_series))
                    if unique_count > 50 and unique_count > int(0.2 * max(n_rows, 1)) and pd.api.types.is_numeric_dtype(y_series):
                        st.error(
                            "Your label column looks continuous (many unique numeric values). "
                            "This app currently supports classification only. "
                            "Please upload a dataset whose last column is a categorical class label (e.g., normal/attack)."
                        )
                        return
                except Exception:
                    pass


                #Splitting training and testing dataframes here
                Dataframe.X_train, Dataframe.X_test, Dataframe.y_train, Dataframe.y_test = train_test_split(Dataframe.X, Dataframe.y, test_size=Dataframe.ratio, random_state=1234)
                y_train_1d = np.ravel(Dataframe.y_train)
                y_test_1d = np.ravel(Dataframe.y_test)

                #Reshape dataframes for ANN models
                #if(classifier_name == 'LSTM'):
                #    Dataframe.X_train = np.reshape(np.ravel(Dataframe.X_train), (Dataframe.X_train.shape[0], 1, Dataframe.X_train.shape[1]))
                #    Dataframe.X_test = np.reshape(np.ravel(Dataframe.X_test), (Dataframe.X_test.shape[0], 1, Dataframe.X_test.shape[1]))
                
                
                classifier_factory = ClassifierFactory()
                clf = classifier_factory.build_classifier(classifier_name, params)
                st.write(f'Classifier = {classifier_name}')
                with st.spinner('Classification in progress...'):

                    #Start classifier fitting and evaluation
                    start_time = time.time()
                    clf.fit(Dataframe.X_train, y_train_1d)
                    end_time = time.time()
                    st.write("Training time: ",end_time-start_time, "seconds")

                    start_time = time.time()
                    Dataframe.y_pred = clf.predict(Dataframe.X_test)
                    end_time = time.time()
                    st.write("Prediction time: ",end_time-start_time, "seconds")

                    acc = accuracy_score(y_test_1d, Dataframe.y_pred)
                    st.write('Accuracy =', acc)
                    metrics = sklearn.metrics.classification_report(y_test_1d, Dataframe.y_pred)
                    st.text(metrics)
                    st.write("Train score is:", clf.score(Dataframe.X_train, y_train_1d))
                    st.write("Test score is:",clf.score(Dataframe.X_test, y_test_1d))
                    
                    if report_btn:
                        report = sklearn.metrics.classification_report(y_test_1d, Dataframe.y_pred, output_dict=True)
                        Output.generate_report(report)

                    # Store trained model for live inference
                    st.session_state.trained_clf = clf
                    st.session_state.trained_classifier_name = classifier_name
                    st.session_state.trained_feature_columns = list(Dataframe.X.columns)
                    st.session_state.trained_normal_label = getattr(Dataframe, "normal_label", None)
                    st.session_state.trained_flow_mode = bool(getattr(Dataframe, "flow_mode", False))
                    st.session_state.trained_flow_drop_ip = bool(getattr(Dataframe, "flow_drop_ip", True))

                    with st.expander("Explain model predictions (SHAP)"):
                        if classifier_name in ('Random Forest', 'Gradient Boosting Classifier'):
                            try:
                                shap_sample = Dataframe.X_test
                                if len(shap_sample) > 200:
                                    shap_sample = shap_sample.sample(200, random_state=1234)

                                explainer = shap.TreeExplainer(clf)
                                shap_values = explainer.shap_values(shap_sample)

                                st.write("Global feature importance based on SHAP values:")
                                shap.summary_plot(shap_values, shap_sample, show=False)
                                st.pyplot(bbox_inches="tight")
                            except Exception as e:
                                st.warning(f"Could not compute SHAP explanations: {e}")
                        else:
                            st.info("SHAP explanations are currently implemented for tree-based models (Random Forest, Gradient Boosting Classifier).")

                    st.success('Done!')
                
            else: 
                st.write('Click the button to classify')



#Instantiating the classifier selected in the sidebar --> Applying Python Factory Pattern Here (Callable Factory)
class ClassifierFactory(object):
    def build_classifier(self, clf_name, params): #Foremely get_classifier
        clf = None
        if clf_name == 'SVM':
            from sklearn.svm import SVC
            clf = SVC(C=params['C'], kernel=params['kernel'], degree=params['degree'])
        if clf_name == 'KNN':
            from sklearn.neighbors import KNeighborsClassifier
            clf = KNeighborsClassifier(n_neighbors=params['K'], algorithm=params['algorithm'], p=params['p'], n_jobs=params['n_jobs'])
        if clf_name == 'Naive Bayes':
            from sklearn.naive_bayes import GaussianNB
            clf = GaussianNB()
        if clf_name == 'Random Forest':
            from sklearn.ensemble import RandomForestClassifier
            clf = RandomForestClassifier(n_estimators=params['n_estimators'], 
                max_depth=params['max_depth'], random_state=1234, min_samples_split=params['min_samples_split'], n_jobs=params['n_jobs'], criterion=params['criterion'])
        if clf_name == 'Decision Tree':
            from sklearn.tree import DecisionTreeClassifier
            clf = DecisionTreeClassifier(criterion=params['criterion'], splitter=params['splitter'], max_depth = params['max_depth'], min_samples_split=params['min_samples_split'], min_samples_leaf=params['min_samples_leaf'])
        if clf_name == 'Logistic Regression':
            from sklearn.linear_model import LogisticRegression
            clf = LogisticRegression(max_iter=params['max_iter'], solver=params['solver'], penalty=params['penalty'], n_jobs=params['n_jobs'])
        if clf_name == 'Gradient Boosting Classifier':
            from sklearn.ensemble import GradientBoostingClassifier
            clf = GradientBoostingClassifier(n_estimators=params['n_estimators'], loss=params['loss'], max_depth=params['max_depth'])
        if clf_name == 'LSTM':
            from keras.wrappers.scikit_learn import KerasClassifier
            from keras.models import Sequential
            from keras.layers import Dense
            from keras.layers import LSTM
            def lstm():
                model = Sequential()
                #model.add(Dense(41,input_dim=41,activation = 'relu',kernel_initializer='random_uniform'))
                #model.add(Dense(41,activation='sigmoid',kernel_initializer='random_uniform'))
                #model.add(LSTM((1),batch_input_shape=(None, 1, Dataframe.X_train.shape[1]), return_sequences=False))
                #model.add(LSTM(units = 23, return_sequences = True, input_shape= (41, 1, 1)))
                #model.add(LSTM(1, input_shape=(50, 41)))

                model.add(Dense(40,input_dim =41,activation = 'relu',kernel_initializer='random_uniform'))
                model.add(Dense(1,activation='sigmoid',kernel_initializer='random_uniform'))
                
                model.compile(loss ='categorical_crossentropy',optimizer = 'adam',metrics = ['accuracy'])
                return model
            clf = KerasClassifier(build_fn=lstm,epochs=3,batch_size=64)
        if clf_name == 'Neural Networks':
            from sklearn.neural_network import MLPClassifier
            clf = MLPClassifier(**params)
        return clf
        


class Output:
    def generate_report(report):
        stdf = pd.DataFrame(report).transpose()
        st.dataframe(stdf)
        stdf.to_csv (f'MetricsReports\{classifier_name}.csv', index = True, header=True)

    def show_metrics_reports():
        st.header("Metrics Reports: ")
        directory="MetricsReports"
        for filename in os.listdir(directory):
            if filename.endswith(".csv"): 
                st.subheader(filename[:-4])
                metric_csv = pd.read_csv(os.path.join(directory, filename))
                st.write(metric_csv)
                continue
            else:
                continue





uploaded_file = None
uploaded_file = st.file_uploader("Choose a file")

if uploaded_file is not None:
    DataInput.read_data()

# -----------------------
# Live local packet monitor (Windows via Npcap)
# -----------------------
st.sidebar.header("Live Network Monitor (local)")

auto_refresh = st.sidebar.checkbox("Auto-refresh while capturing", value=True)
refresh_ms = st.sidebar.slider("Refresh interval (ms)", 200, 5000, 1000, 100)

if "live_sniffer" not in st.session_state:
    st.session_state.live_sniffer = None

def _flow_key(pkt):
    ip = None
    if IP is not None and pkt.haslayer(IP):
        ip = pkt[IP]
    elif IPv6 is not None and pkt.haslayer(IPv6):
        ip = pkt[IPv6]
    else:
        return None
    proto = "other"
    sport = dport = 0
    if TCP is not None and pkt.haslayer(TCP):
        proto = "tcp"
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
    elif UDP is not None and pkt.haslayer(UDP):
        proto = "udp"
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
    return (str(ip.src), str(ip.dst), sport, dport, proto)

def _on_packet(pkt):
    key = _flow_key(pkt)
    if key is None:
        return
    now = time.time()
    pkt_len = 0
    try:
        pkt_len = int(len(pkt))
    except Exception:
        pkt_len = 0
    live_lock, live_flows, live_total = get_live_store()
    with live_lock:
        entry = live_flows[key]
        if entry["first_ts"] is None:
            entry["first_ts"] = now
        entry["last_ts"] = now
        entry["packets"] += 1
        entry["bytes"] += pkt_len
        live_total["packets"] += 1
        live_total["bytes"] += pkt_len
        live_total["last_ts"] = now

col_a, col_b = st.sidebar.columns(2)
start_capture = col_a.button("Start capture")
stop_capture = col_b.button("Stop capture")

iface_options = []
if get_if_list is not None:
    try:
        iface_options = list(get_if_list())
    except Exception:
        iface_options = []
iface = st.sidebar.selectbox("Interface", options=["(default)"] + iface_options, index=0)
use_filter = st.sidebar.checkbox("Use BPF filter", value=False)
capture_filter = st.sidebar.text_input("BPF filter", value="ip or ip6", disabled=(not use_filter))
max_rows = st.sidebar.slider("Max flows to show", 50, 2000, 300, 50)
sniff_self_test = st.sidebar.button("Self-test capture (3s)")

if AsyncSniffer is None:
    st.sidebar.warning("Scapy could not be imported. Install Npcap (WinPcap compatible mode) and restart the app.")
else:
    running = st.session_state.live_sniffer is not None
    st.sidebar.caption(f"Capture status: {'RUNNING' if running else 'stopped'}")
    live_lock, live_flows, live_total = get_live_store()
    with live_lock:
        st.sidebar.caption(f"Packets seen: {int(live_total.get('packets') or 0)}")
    if "live_last_error" in st.session_state and st.session_state.live_last_error:
        st.sidebar.error(f"Last capture error: {st.session_state.live_last_error}")

    if sniff_self_test:
        try:
            from scapy.all import sniff  # type: ignore

            test_kwargs = {"timeout": 3, "store": True}
            if iface != "(default)":
                test_kwargs["iface"] = iface
            if use_filter and capture_filter.strip():
                test_kwargs["filter"] = capture_filter.strip()
            pkts = sniff(**test_kwargs)
            st.sidebar.success(f"Self-test captured {len(pkts)} packets in 3s.")
        except Exception as e:
            st.sidebar.error(f"Self-test failed: {e}")

    if start_capture and st.session_state.live_sniffer is None:
        try:
            st.session_state.live_last_error = ""
            live_lock, live_flows, live_total = get_live_store()
            with live_lock:
                live_flows.clear()
                live_total["packets"] = 0
                live_total["bytes"] = 0
                live_total["last_ts"] = None
            kwargs = {"prn": _on_packet, "store": False}
            if iface != "(default)":
                kwargs["iface"] = iface
            if use_filter and capture_filter.strip():
                kwargs["filter"] = capture_filter.strip()
            st.session_state.live_sniffer = AsyncSniffer(**kwargs)
            st.session_state.live_sniffer.start()
            st.sidebar.success("Capture started.")
        except Exception as e:
            st.session_state.live_sniffer = None
            st.session_state.live_last_error = str(e)
            st.sidebar.error(f"Failed to start capture: {e}")

    if stop_capture and st.session_state.live_sniffer is not None:
        try:
            st.session_state.live_sniffer.stop()
        except Exception:
            pass
        st.session_state.live_sniffer = None
        st.sidebar.success("Capture stopped.")

    if auto_refresh and st.session_state.live_sniffer is not None:
        st_autorefresh(interval=refresh_ms, key="live_capture_refresh")

st.subheader("Live flows (local capture)")

flows_items = []
live_lock, live_flows, live_total = get_live_store()
with live_lock:
    flows_snapshot = list(live_flows.items())
    totals_snapshot = dict(live_total)

for (src, dst, sport, dport, proto), v in flows_snapshot:
    first_ts = v["first_ts"]
    last_ts = v["last_ts"]
    duration = (last_ts - first_ts) if (first_ts is not None and last_ts is not None) else 0.0
    flows_items.append(
        {
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
            "packets": v["packets"],
            "bytes": v["bytes"],
            "duration_s": round(duration, 3),
        }
    )

flows_df = pd.DataFrame(flows_items)
if not flows_df.empty:
    flows_df = flows_df.sort_values(["bytes", "packets"], ascending=False).head(int(max_rows))

    k1, k2, k3 = st.columns(3)
    k1.metric("Active flows", int(len(flows_snapshot)))
    k2.metric("Total packets", int(totals_snapshot.get("packets") or 0))
    k3.metric("Total bytes", int(totals_snapshot.get("bytes") or 0))

    last_seen = totals_snapshot.get("last_ts")
    if last_seen is None:
        st.caption("Last packet: (none yet)")
    else:
        st.caption(f"Last packet: {time.strftime('%H:%M:%S', time.localtime(float(last_seen)))}")

    st.write("Protocol mix (by bytes):")
    proto_mix = flows_df.groupby("protocol", as_index=False)["bytes"].sum().sort_values("bytes", ascending=False)
    st.bar_chart(proto_mix.set_index("protocol")["bytes"])

    st.dataframe(flows_df, use_container_width=True)

    with st.expander("Live classification (experimental)", expanded=False):
        clf = st.session_state.get("trained_clf")
        feature_cols = st.session_state.get("trained_feature_columns")
        normal_label = st.session_state.get("trained_normal_label")
        trained_flow_mode = st.session_state.get("trained_flow_mode", False)
        trained_flow_drop_ip = st.session_state.get("trained_flow_drop_ip", True)
        trained_scaler = st.session_state.get("trained_scaler", None)

        if clf is None or not feature_cols:
            st.info("Train a model first (click 'Classify') to enable live predictions.")
        else:
            if trained_flow_mode:
                st.caption("Live classification uses the same flow-feature builder as training (feature parity).")
                X_live_built, _ = build_flow_features(
                    flows_df,
                    fit=False,
                    drop_ip=trained_flow_drop_ip,
                    label_col=None,
                )

                # Align column order / missing columns
                X_live = pd.DataFrame(0, index=X_live_built.index, columns=feature_cols, dtype=float)
                for c in X_live_built.columns:
                    if c in X_live.columns:
                        X_live[c] = X_live_built[c].astype(float)
            else:
                st.caption("Live flow features are mapped into your model's feature columns; unknown features are filled with 0. This is an approximation.")
                X_live = pd.DataFrame(0, index=flows_df.index, columns=feature_cols, dtype=float)

                # Common KDD-style mappings (best-effort)
                if "duration" in X_live.columns:
                    X_live["duration"] = flows_df["duration_s"].astype(float)
                if "protocol_type" in X_live.columns:
                    proto_str = flows_df["protocol"].astype(str)
                    if hasattr(Dataframe, "encoders") and "protocol_type" in getattr(Dataframe, "encoders", {}):
                        le = Dataframe.encoders["protocol_type"]
                        known = set(le.classes_)
                        X_live["protocol_type"] = proto_str.apply(lambda v: le.transform([v])[0] if v in known else -1)
                    else:
                        X_live["protocol_type"] = proto_str.map({"tcp": 0, "udp": 1}).fillna(-1)
                if "src_bytes" in X_live.columns:
                    X_live["src_bytes"] = flows_df["bytes"].astype(float)
                if "dst_bytes" in X_live.columns:
                    X_live["dst_bytes"] = 0.0
                if "count" in X_live.columns:
                    X_live["count"] = flows_df["packets"].astype(float)

                for col in ["src_port", "dst_port", "packets", "bytes", "duration_s"]:
                    if col in X_live.columns and col in flows_df.columns:
                        X_live[col] = flows_df[col].astype(float)

            if trained_scaler is not None:
                try:
                    X_live[X_live.columns] = trained_scaler.transform(X_live)
                except Exception:
                    pass

            # Predict
            try:
                y_live = clf.predict(X_live)
                y_live = pd.Series(y_live).astype(str)

                if normal_label is None:
                    normal_label = y_live.mode(dropna=True)[0] if len(y_live) else None

                if normal_label is not None:
                    is_suspicious = y_live != str(normal_label)
                else:
                    is_suspicious = pd.Series([False] * len(y_live))

                c1, c2, c3 = st.columns(3)
                c1.metric("Predicted normal", int((~is_suspicious).sum()))
                c2.metric("Predicted suspicious", int(is_suspicious.sum()))
                c3.metric("Unique labels", int(y_live.nunique()))

                out_df = flows_df.copy()
                out_df["pred_label"] = y_live.values
                out_df["suspicious"] = is_suspicious.values

                st.write("Top suspicious flows (by bytes):")
                susp_df = out_df[out_df["suspicious"]].sort_values(["bytes", "packets"], ascending=False).head(50)
                if susp_df.empty:
                    st.success("No suspicious flows detected (under current mapping/model).")
                else:
                    st.dataframe(susp_df, use_container_width=True)
            except Exception as e:
                st.warning(f"Live prediction failed: {e}")

    export_name = st.text_input("Export filename", value="live_flows.csv")
    st.download_button(
        "Download captured flows CSV",
        data=flows_df.to_csv(index=False).encode("utf-8"),
        file_name=export_name,
        mime="text/csv",
    )
else:
    st.info("No flows captured yet. Click 'Start capture' in the sidebar.")

#Populating classification sidebar here
st.sidebar.header("Classification")
classifier_name = st.sidebar.selectbox(
    'Select classifier',
    ('Naive Bayes', 'KNN', 'SVM', 'Random Forest', 'Decision Tree', 'Logistic Regression', 'Gradient Boosting Classifier', 'Neural Networks')
)
params = Classifier.add_parameters(classifier_name)

report_btn = st.checkbox("Add classification task to Metrics Report")

Classifier.get_prediction()


st.sidebar.subheader("Metrics Reports")
metrics_reports_btn = st.sidebar.button("Show Metrics Reports")
if metrics_reports_btn:
    Output.show_metrics_reports()
