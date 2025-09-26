#!/bin/bash

# Script to test different threshold values for GNNSCModel
# Usage: ./test_thresholds.sh <train_file> <valid_file> [base_exp_name]

# Check if required arguments are provided
if [ $# -lt 2 ]; then
    echo "Usage: $0 <train_file> <valid_file> [base_exp_name]"
    echo "Example: $0 train.json valid.json experiment1"
    exit 1
fi

TRAIN_FILE=$1
VALID_FILE=$2
BASE_EXP_NAME=${3:-"threshold_test"}

# Check if files exist
if [ ! -f "$TRAIN_FILE" ]; then
    echo "Error: Training file '$TRAIN_FILE' not found"
    exit 1
fi

if [ ! -f "$VALID_FILE" ]; then
    echo "Error: Validation file '$VALID_FILE' not found"
    exit 1
fi

# Create logs directory if it doesn't exist
mkdir -p logs/threshold_tests

echo "=========================================="
echo "  Threshold Testing Script"
echo "=========================================="
echo "Train file: $TRAIN_FILE"
echo "Valid file: $VALID_FILE"
echo "Base experiment name: $BASE_EXP_NAME"
echo "=========================================="
echo ""

# Array of threshold values to test (using author's original values)
THRESHOLDS=(0.352 0.38 0.4 0.42 0.45 0.48 0.5 0.52 0.55)

# Create summary file
SUMMARY_FILE="logs/threshold_tests/${BASE_EXP_NAME}_summary.csv"
echo "threshold,accuracy,precision,recall,f1,pred_0,pred_1" > "$SUMMARY_FILE"

echo "Testing ${#THRESHOLDS[@]} threshold values: ${THRESHOLDS[@]}"
echo ""

# Test each threshold
for threshold in "${THRESHOLDS[@]}"; do
    echo "=========================================="
    echo "Testing threshold: $threshold"
    echo "=========================================="

    EXP_NAME="${BASE_EXP_NAME}_th${threshold}"
    LOG_FILE="logs/threshold_tests/${EXP_NAME}.log"

    # Run the model with current threshold
    python3 GNNSCModel.py \
        --train-file "$TRAIN_FILE" \
        --valid-file "$VALID_FILE" \
        --random_seed 9930 \
        --thresholds "$threshold" \
        --verbose \
        --exp_name "$EXP_NAME" \
        2>&1 | tee "$LOG_FILE"

    # Extract results from the generated CSV file
    RESULT_CSV="res_${EXP_NAME}.csv"
    if [ -f "$RESULT_CSV" ]; then
        # Read the second line (first line is header)
        RESULT_LINE=$(sed -n '2p' "$RESULT_CSV")
        if [ ! -z "$RESULT_LINE" ]; then
            # Add threshold value at the beginning
            echo "${threshold},${RESULT_LINE#*,}" >> "$SUMMARY_FILE"
            echo "Results saved for threshold $threshold"
        fi
    else
        echo "Warning: Result file $RESULT_CSV not found"
    fi

    # Also check validation CSV for prediction counts
    VALID_CSV="valid_${EXP_NAME}.csv"
    if [ -f "$VALID_CSV" ]; then
        echo ""
        echo "Validation prediction distribution (last epoch):"
        tail -n 1 "$VALID_CSV" | awk -F',' '{print "  Predicted as 0: " $7 "\n  Predicted as 1: " $8}'
    fi

    echo ""
done

echo "=========================================="
echo "  Threshold Testing Complete!"
echo "=========================================="
echo "Summary saved to: $SUMMARY_FILE"
echo ""
echo "Summary of results:"
echo "-------------------"
column -t -s',' "$SUMMARY_FILE" | head -20

# Find best threshold based on F1 score
echo ""
echo "Best threshold based on F1 score:"
echo "---------------------------------"
BEST_LINE=$(tail -n +2 "$SUMMARY_FILE" | sort -t',' -k5 -rn | head -1)
BEST_THRESHOLD=$(echo "$BEST_LINE" | cut -d',' -f1)
BEST_F1=$(echo "$BEST_LINE" | cut -d',' -f5)
echo "Threshold: $BEST_THRESHOLD (F1: $BEST_F1)"