import pandas as pd
from mlxtend.frequent_patterns import apriori
from mlxtend.preprocessing import TransactionEncoder
from mlxtend.frequent_patterns import association_rules

df=pd.read_csv("D:\\IST paper\\frequent itemset\\total occurence.csv")


#print(df['commentid'])
#print(df)

#print(apriori(df, min_support=0.5))

#df = pd.DataFrame(te_ary, columns=te.columns_)

frequent_itemsets = apriori(df, min_support=0.2, use_colnames=True)
#print (frequent_itemsets.rank(ascending=False))
# print (frequent_itemsets)

#df['rank'] = df.groupby('cust_ID')['transaction_count'].rank(ascending=False)

# lists of columns where value is 1 per row
# cols = df.dot(df.columns).map(set).values.tolist()
# # use sets to see which rows are a superset of the sets in cols
# set_itemsets = map(set,frequent_itemsets.itemsets.values.tolist())
# frequent_itemsets['indices'] = [[ix for ix,j in enumerate(cols) if i.issubset(j)]
#                                  for i in set_itemsets]

print(frequent_itemsets)
