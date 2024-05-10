import pandas as pd

password_df = pd.read_csv('password_database_ED2.csv')
rockyou_df = pd.read_csv('rockyou.txt')

row = password_df[password_df['username'] == 'kjtorregrosa']
print(row)
