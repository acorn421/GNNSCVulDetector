contract Wallet {
     
    function execute(address destination, uint amount, bytes calldata payload) external returns (uint) {
        if (amount > 0) {
            destination.call.value(amount)(payload);
            return 0;
        }
    }
}