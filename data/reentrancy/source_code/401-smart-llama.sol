contract ManagedAccount {

    // Sends specified amount to the recipient
    function payOut(address recipient, uint amount) returns (bool success) {
        if (recipient.call.value(amount)()) {
            return true;
        } else {
            return false;
        }
    }
}