contract CampaignBeneficiary {

    address public resilienceAddress;

    // Simulates the pathway from the beneficiary by calling the buy function
    function simulatePathwayFromBeneficiary() public payable {
        bytes4 buyFunctionSignature = bytes4(sha3("buy()"));
        if (!resilienceAddress.call.value(msg.value)(buyFunctionSignature)) {
            revert();
        }
    }
}