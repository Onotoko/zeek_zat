
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
from dotenv import load_dotenv
import zat
from zat.log_to_dataframe import LogToDataFrame
from zat.dataframe_to_matrix import DataFrameToMatrix
import pandas as pd
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
from pathlib import Path
# from sklearn.model_selection import train_test_split
# from pyod.models import lof
# from pyod.models.abod import ABOD
# from pyod.models.cblof import CBLOF
# from pyod.models.lof import LOF
# from pyod.models.loci import LOCI
# from pyod.models.lscp import LSCP
# from pyod.models.mcd import MCD
# from pyod.models.ocsvm import OCSVM
from pyod.models.pca import PCA
# from pyod.models.sod import SOD
# from pyod.models.so_gaal import SO_GAAL # Needs keras
# from pyod.models.sos import SOS  # Needs keras
# from pyod.models.xgbod import XGBOD # Needs keras
# from pyod.models.knn import KNN   # kNN detector
import argparse
import warnings

load_dotenv()

class Watcher:
    DIRECTORY_TO_WATCH = os.getenv("DIRECTORY_TO_WATCH")

    def __init__(self):
        self.observer = Observer()

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except:
            self.observer.stop()
            print ("Error")

        self.observer.join()


class Handler(FileSystemEventHandler):

    @staticmethod
    def on_any_event(event):
        if event.is_directory:
            return None

        elif event.event_type == 'created':
            # Take any action here when a file is first created.
            print ("Received created event - %s." % event.src_path)
            if Path(event.src_path).suffix == '.log':
                detect(event.src_path, 10)


# This horrible hack is only to stop sklearn from printing those warnings
def warn(*args, **kwargs):
    pass


warnings.warn = warn


def detect(file, amountanom):
    """
    Function to apply a very simple anomaly detector
    amountanom: The top number of anomalies we want to print
    """

    # read data
    log_to_df = LogToDataFrame()
    zeek_df = log_to_df.create_dataframe(file)
    #print('Read in {:d} Rows...'.format(len(zeek_df)))

    # In case you need a label, due to some models being able to work in a
    # semisupervized mode, then put it here. For now everything is
    # 'normal', but we are not using this for detection
    zeek_df['label'] = 'normal'

    # Replace the rows without data (with '-') with 0.
    # Even though this may add a bias in the algorithms,
    # is better than not using the lines.
    # Also fill the no values with 0
    # Finally put a type to each column
    zeek_df['orig_bytes'].replace('-', '0', inplace=True)
    zeek_df['orig_bytes'] = zeek_df['orig_bytes'].fillna(0).astype('int32')
    zeek_df['resp_bytes'].replace('-', '0', inplace=True)
    zeek_df['resp_bytes'] = zeek_df['resp_bytes'].fillna(0).astype('int32')
    zeek_df['resp_pkts'].replace('-', '0', inplace=True)
    zeek_df['resp_pkts'] = zeek_df['resp_pkts'].fillna(0).astype('int32')
    zeek_df['orig_ip_bytes'].replace('-', '0', inplace=True)
    zeek_df['orig_ip_bytes'] = zeek_df['orig_ip_bytes'].fillna(0).astype('int32')
    zeek_df['resp_ip_bytes'].replace('-', '0', inplace=True)
    zeek_df['resp_ip_bytes'] = zeek_df['resp_ip_bytes'].fillna(0).astype('int32')
    # zeek_df['duration'].replace('-', '0', inplace=True)
    # zeek_df['duration'] = zeek_df['duration'].fillna(0).astype('float64')

    features = ['duration', 'orig_bytes', 'id.resp_p', 'resp_bytes', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes']
    # Add the columns from the log file that we know are numbers. This is only for conn.log files.
    to_matrix = DataFrameToMatrix()
    zeek_matrix = to_matrix.fit_transform(zeek_df[features], normalize=True)

    X_train = zeek_matrix

    # Our y is the label. But we are not using it now.
    y = zeek_df.label

    # The X_test is where we are going to search for anomalies. In our case, its the same set of data than X_train.
    # X_test = X_train
    odd_clf = IsolationForest(behaviour='new', contamination=0.25) # Marking 25% odd
    odd_clf.fit(zeek_matrix)
    odd_df = zeek_df[features][odd_clf.predict(zeek_matrix) == -1]
    print(odd_df.shape)
    #################
    # Select a model from below

    # ABOD class for Angle-base Outlier Detection. For an observation, the
    # variance of its weighted cosine scores to all neighbors could be
    # viewed as the outlying score.
    # clf = ABOD()

    # LOF
    # clf = LOF()

    # CBLOF
    # clf = CBLOF()

    # LOCI
    # clf = LOCI()

    # LSCP
    # clf = LSCP()

    # MCD
    # clf = MCD()

    # OCSVM
    # clf = OCSVM()

    # PCA. Good and fast!
    # clf = PCA()

    # SOD
    # clf = SOD()

    # SO_GAAL
    # clf = SO_GALL()

    # SOS
    # clf = SOS()

    # XGBOD
    # clf = XGBOD()

    # KNN
    # Good results but slow
    # clf = KNN()
    # clf = KNN(n_neighbors=10)
    #################

    # Fit the model to the train data
    # clf.fit(X_train)

    # # get the prediction on the test data
    # y_test_pred = clf.predict(X_test)  # outlier labels (0 or 1)

    # y_test_scores = clf.decision_function(X_test)  # outlier scores

    # # Convert the ndarrays of scores and predictions to  pandas series
    # scores_series = pd.Series(y_test_scores)
    # pred_series = pd.Series(y_test_pred)

    # # Now use the series to add a new column to the X test
    # X_test['score'] = scores_series.values
    # X_test['pred'] = pred_series.values

    # # Add the score to the bro_df also. So we can show it at the end
    # bro_df['score'] = X_test['score']

    # # Keep the positive predictions only. That is, keep only what we predict is an anomaly.
    # X_test_predicted = X_test[X_test.pred == 1]

    # # Keep the top X amount of anomalies
    # top10 = X_test_predicted.sort_values(by='score', ascending=False).iloc[:amountanom]

    # # Print the results
    # # Find the predicted anomalies in the original bro dataframe, where the rest of the data is
    # df_to_print = bro_df.iloc[top10.index]
    # print('\nFlows of the top anomalies')

    # # Only print some columns, not all, so its easier to read.
    # df_to_print = df_to_print.drop(['conn_state', 'history', 'local_orig', 'local_resp', 'missed_bytes', 'ts', 'tunnel_parents', 'uid', 'label'], axis=1)
    # print(df_to_print)

if __name__ == '__main__':
    # w = Watcher()
    # w.run()
    detect("/home/nobita/Documents/pizzlysoft/zeek_zat/test/conn.log", 10)