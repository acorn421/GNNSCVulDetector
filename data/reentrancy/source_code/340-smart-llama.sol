contract MoldCoin {
     
    address public owner;

    // Purchase function that sends ETH to the owner
    function purchase(address beneficiary) payable {
        if(!owner.call.value(msg.value)()) revert();
    }
}