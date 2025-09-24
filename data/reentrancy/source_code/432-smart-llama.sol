contract Reentrance {
    // Mapping to store user balances
    mapping (address => uint) private balances;

    // Function to withdraw user's balance
    function withdrawBalance() external {
        // Send funds to caller
        if( !(msg.sender.call.value(balances[msg.sender])()) ){ 
            revert(); 
        }
        // Reset balance after sending
        balances[msg.sender] = 0;
    }
}