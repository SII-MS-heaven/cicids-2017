## CICIDS-2017 dataset processing

This repository describes how to train Machine Learning based NIDS from the [**CICIDS-2017**](https://www.unb.ca/cic/datasets/ids-2017.html) dataset. In particular, it lays out all necessary steps to produce ML/DL exploitable files by processing the raw `pcap` collected in the experiment presented in [[1]](#references).

It is organized according to the following steps and notebooks:
1. Flows are first generated from the experiment raw `pcap` with [Zeek](https://docs.zeek.org/en/master/).
2. They are then labelled with [`zeek_labelling.ipynb`](zeek_labelling.ipynb).
3. ML-based models are finally trained and evaluated with [`zeek_ml.ipynb`](zeek_ml.ipynb).

**Note**: Friday's experiment is used to compare results (e.g. flow numbers per attack) with results in the literature but the same steps can easily be adapted to any other day.

### Requirements

First clone and move to the present directory:
```sh
git clone https://github.com/SII-MS-heaven/cicids-2017.git
cd cicids-2017
```

#### CICIDS-2017 dataset

The CICIDS-2017 pcap files can be downloaded at [this address](https://www.unb.ca/cic/datasets/ids-2017.html):
```sh
# Index of /CICDataset/CIC-IDS-2017/Dataset
Dataset/PCAPs/Friday-WorkingHours.pcap
```

You can then move this file to `cicids-2017`.

#### Zeek

All installation guidelines are available at [this link](https://docs.zeek.org/en/master/install.html). For an Ubuntu 22.04, these instructions are:
```sh
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt update
sudo apt install zeek
```

**Note**: please be aware that Zeek is not compatible with [WSL v1](https://github.com/zeek/zeek/issues/504) but it has a [Docker image](https://hub.docker.com/u/zeek) and a Windows experimental build procedure.

#### Python dependencies

The notebook dependencies are `numpy`, `pandas`, `plotly` and `scikit-learn`. They can be installed in a virtual environment by running:
```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install upgrade pip
pip install -r requirements.txt
```

### Extracting flows with Zeek

For an Ubuntu 22.04, `Friday-WorkingHours.pcap` can be processed with the following command:
```sh
/opt/zeek/bin/zeek -C -r Friday-WorkingHours.pcap Log::default_logdir=friday_zeek_logs
```
which will produce a `friday_zeek_logs` folder containing various log files in `TSV` format (i.e. `.csv` file with tabulation separators).

As suggested in [[2]](#references), the data analysis should then focus on [`conn.log`](https://docs.zeek.org/en/current/logs/conn.html#conn-log) which will be labelled next.

### Flow labelling - `zeek_labelling.ipynb`

For Friday's experiment, the processing steps are described in the `zeek_labelling.ipynb` notebook. It results in the following label counts:
```py
# Output of cell [9]
label
benign      290779
portscan    160134  # vs 159023  (Engelen), 160106   (Rosay) and 159579  (Lanvin)
ddos         95683  # vs 95123   (Engelen), 95683    (Rosay) and 95144   (Lanvin)
Bot            738  # vs 738     (Engelen), 735      (Rosay) and 738     (Lanvin)
```

After removing information susceptible to bias training, the labelled dataset is finally exported to `friday_dataset.csv` with the following 27 features:
```py
# Output of cell [11]
retained input features: 
--> duration
--> orig_bytes
--> resp_bytes
--> missed_bytes
--> orig_pkts
--> orig_ip_bytes
--> resp_pkts
--> resp_ip_bytes
--> proto_icmp
--> proto_tcp
--> proto_udp
--> local_orig_F
--> local_orig_T
--> local_resp_F
--> local_resp_T
--> conn_state_OTH
--> conn_state_REJ
--> conn_state_RSTO
--> conn_state_RSTR
--> conn_state_RSTRH
--> conn_state_S0
--> conn_state_S1
--> conn_state_S2
--> conn_state_S3
--> conn_state_SF
--> conn_state_SH
--> conn_state_SHR
```

**Credit**:
This notebook was inspired from code available in the following git repositories:
- [WTMC2021-Code](https://github.com/GintsEngelen/WTMC2021-Code/blob/main/labelling_CSV_flows.py) which comes with [[3]](#references).
- [LYCOS-IDS2017](https://maupiti-git.univ-lemans.fr/lycos/lycos-ids2017/src/master/labelling.py) which comes with [[4]](#references).

### Model training - `zeek_ml.ipynb`

The labelled connection record `friday_dataset.csv` can finally be used to train ML models with `zeek_ml.ipynb`. It should yield the following performances:

|FPR	|Prec	|TPR	|F1-score	|Support	|Model	|Exp|
|---|---|---|---|---|---|---|
|0.000000|1.000000|1.000000|1.000000|179589.0|Decision Tree Classifier|Train|
|0.000054|0.999922|0.999961|0.999942|76966.0|Decision Tree Classifier|Test|
|0.000089|0.999911|0.996481|0.998193|179589.0|Naive Bayes Classifier|Train|
|0.000054|0.999922|0.996518|0.998217|76966.0|Naive Bayes Classifier|Test|
|0.000000|1.000000|1.000000|1.000000|179589.0|Random Forest|Train|
|0.000009|0.999987|0.999948|0.999968|76966.0|Random Forest|Test|
|0.000128|0.999872|0.996704|0.998285|179589.0|SVM Classifier|Train|
|0.000117|0.999831|0.996804|0.998315|76966.0|SVM Classifier|Test|

**Credit**:
This notebook was inspired from code available in the following git repository:
- [crisis2022](https://gitlab.inria.fr/mlanvin/crisis2022) which comes with [[5]](#references).

### References

- [1] Iman Sharafaldin et al., "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", 4th International Conference on Information Systems Security and Privacy (ICISSP), 2018 ([doi](https://www.scitepress.org/Link.aspx?doi=10.5220/0006639801080116)).
- [2] M. Rodriguez et al., "Evaluation of Machine Learning Techniques for Traffic Flow-Based Intrusion Detection", 2023 ([doi](https://doi.org/10.3390/s22239326)).
- [3] G. Engelen et al., "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study", 2021 ([doi](https://doi.org/10.1109/SPW53761.2021.00009) - [researchgate](https://www.researchgate.net/publication/353107141_Troubleshooting_an_Intrusion_Detection_Dataset_the_CICIDS2017_Case_Study)).
- [4] A. Rosay et al., "Network Intrusion Detection: A Comprehensive Analysis of CIC-IDS2017", 2022 ([doi](https://www.scitepress.org/Link.aspx?doi=10.5220/0010774000003120)).
- [5] M. Lanvin et al., "Errors in the CICIDS2017 dataset and the significant differences in detection performances it makes", 2022 ([doi](https://doi.org/10.1007/978-3-031-31108-6_2) - [hal](https://hal.science/hal-03775466)).