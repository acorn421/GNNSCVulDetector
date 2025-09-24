contract SimpleBet {

    bool isLocked = false;

    function bet() payable {
        // Check if the bet amount is correct and the contract is not locked
        if ((msg.value == 1 ether) && (!isLocked)) {
            // Attempt to send 2 ether back to the sender
            if (!msg.sender.call.value(2 ether)())
                isLocked = true;
                throw;
        }
    }
}