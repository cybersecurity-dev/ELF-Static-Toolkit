def remove_unique_column(df_local):
    # Find columns with identical values
    cols_to_drop = []
    for col in df_local.columns:
        if df_local[col].nunique() == 1:  # Check if there's only one unique value
            cols_to_drop.append(col)

    # Drop the columns
    return df_local.drop(cols_to_drop, axis=1)

def remove_duplicate_columns(df_local):
    # Create an empty set to store unique column data
    unique_cols = []
    columns_to_keep = []

    for col in df_local.columns:
        # Convert the column to a tuple so it can be compared
        col_data = tuple(df_local[col])
        
        if col_data not in unique_cols:
            # If the column data is unique, add it to the unique set
            unique_cols.append(col_data)
            columns_to_keep.append(col)
    
    # Create a new DataFrame with only the unique columns
    return df_local[columns_to_keep]

def replace_nan_with_zero(df_local):
    return df_local.fillna(0)  # Use fillna() to replace NaN with 0