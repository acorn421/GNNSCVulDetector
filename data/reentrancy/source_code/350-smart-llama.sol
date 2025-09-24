contract generic_holder {

    function execute(address destination, uint amount, bytes memory payload) external returns (bool) {
        return destination.call.value(amount)(payload);
    }
}