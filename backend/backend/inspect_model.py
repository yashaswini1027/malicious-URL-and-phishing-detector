import joblib

model = joblib.load('model.pkl')

# Works for most scikit-learn estimators/pipelines fitted on a DataFrame
try:
    names = model.feature_names_in_
    print(f"Number of features expected: {len(names)}")
    print("Feature names, in order:")
    for i, n in enumerate(names):
        print(f"{i}: {n}")
except AttributeError:
    # If it's a Pipeline, the final estimator holds this attribute instead
    try:
        step = model.steps[-1][1]
        names = step.feature_names_in_
        print(f"Number of features expected: {len(names)}")
        print("Feature names, in order:")
        for i, n in enumerate(names):
            print(f"{i}: {n}")
    except Exception as e:
        print("Could not find feature_names_in_ on the model or pipeline.")
        print("Model type:", type(model))
        print("Error:", e)