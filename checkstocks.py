import pandas as pd
from pandas_datareader import data as pdr
import yfinance as yf

yf.pdr_override()

df = pdr.get_data_yahoo ("CSL.AX", start = "2017-12-04", end = "2019-12-06")
print(df)
