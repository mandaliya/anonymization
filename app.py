import streamlit as st
from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine, AnonymizerConfig
from presidio_anonymizer.entities import OperatorConfig
import os

# Initialize Presidio engines
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Streamlit app title and description
st.title("Advanced PII Anonymization with Presidio")
st.write("Enter text to anonymize sensitive information. Select PII entities and anonymization methods:")

# Text input
user_input = st.text_area("Input Text")

# Sidebar for PII entity selection
st.sidebar.header("PII Entities to Detect")
entity_types = ["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "CREDIT_CARD", "DATE_TIME", "LOCATION"]
selected_entities = st.sidebar.multiselect("Select PII entities to detect:", entity_types, default=entity_types)

# Sidebar for anonymization methods
st.sidebar.header("Anonymization Methods")
anonymization_methods = ["mask", "redact", "replace", "hash"]
selected_method = st.sidebar.selectbox("Select anonymization method:", anonymization_methods, index=0)

# Anonymization configuration
anonymization_config = {
    "mask": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 4, "from_end": True}),
    "redact": OperatorConfig("redact", {}),
    "replace": OperatorConfig("replace", {"new_value": "<REDACTED>"}),
    "hash": OperatorConfig("hash", {}),
}

if st.button("Anonymize"):
    if user_input:
        # Analyze text for selected PII entities
        results = analyzer.analyze(text=user_input, entities=selected_entities, language='en')

        # Create anonymization configuration
        config = AnonymizerConfig()
        for result in results:
            config.add_operator(result.entity_type, anonymization_config[selected_method])

        # Anonymize detected PII entities
        anonymized_result = anonymizer.anonymize(text=user_input, analyzer_results=results, anonymizer_config=config)

        st.subheader("Anonymized Text:")
        st.write(anonymized_result.text)
    else:
        st.write("Please enter some text to anonymize.")
