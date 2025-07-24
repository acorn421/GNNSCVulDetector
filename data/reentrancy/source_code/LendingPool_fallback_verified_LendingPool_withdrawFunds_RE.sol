/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawFunds
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a classic reentrancy attack pattern that requires multiple transactions to exploit. First, an attacker must call initiateWithdrawal() to set up the withdrawal state. Then, they can call withdrawFunds() which performs an external call to aDai.transfer() before updating the state variables. If the aDai token contract has a callback mechanism or if the attacker controls the token contract, they can re-enter withdrawFunds() before the state is cleared, allowing them to withdraw funds multiple times while the pendingWithdrawals mapping still shows a positive balance.
 */
pragma solidity ^0.4.24;

contract Ownable {
    address public owner;

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    /**
     * @dev The Ownable constructor sets the original `owner` of the contract to the sender
     * account.
     */
    constructor() public {
        owner = msg.sender;
    }
    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    /**
    * @dev Allows the current owner to transfer control of the contract to a newOwner.
    * @param newOwner The address to transfer ownership to.
    */
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

contract Erc20 {
    function balanceOf(address _owner) public view returns (uint256);
    function transfer(address _to, uint256 _value) public returns (bool);
    function approve(address _spender, uint256 _value) public returns (bool);
}

contract Exchange {
    function ethToTokenSwapInput(uint256 min_tokens, uint256 deadline)
        public
        payable
        returns (uint256);
}

contract LendingPool {
    function deposit( address _reserve, uint256 _amount, uint16 _referralCode) external payable;
}

contract aDaiGateway is Ownable {
    Exchange constant DaiEx = Exchange(0x2a1530C4C41db0B0b2bB646CB5Eb1A67b7158667);
    LendingPool constant lendingPool = LendingPool(0x398eC7346DcD622eDc5ae82352F02bE94C62d119);

    Erc20 constant  dai = Erc20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    Erc20 constant aDai = Erc20(0xfC1E690f61EFd961294b3e1Ce3313fBD8aa4f85d);

    uint16 constant referral = 47;

    // === FALLBACK INJECTION: Reentrancy ===
    // Move state variable declarations to contract scope
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => bool) public withdrawalInProgress;
    // === END FALLBACK INJECTION ===

    constructor() public {
        dai.approve(0x3dfd23A6c5E8BbcFc9581d2E864a68feb6a076d3, uint256(-1)); //lendingPoolCore
    }

    // === FALLBACK INJECTION: Reentrancy ===
    // Move functions out of constructor
    function initiateWithdrawal(uint256 amount) public {
        require(aDai.balanceOf(msg.sender) >= amount, "Insufficient aDai balance");
        require(!withdrawalInProgress[msg.sender], "Withdrawal already in progress");
        pendingWithdrawals[msg.sender] = amount;
        withdrawalInProgress[msg.sender] = true;
    }
    
    function withdrawFunds() public {
        require(withdrawalInProgress[msg.sender], "No withdrawal in progress");
        require(pendingWithdrawals[msg.sender] > 0, "No pending withdrawal");
        uint256 amount = pendingWithdrawals[msg.sender];
        // Transfer aDai first (vulnerable to reentrancy)
        aDai.transfer(msg.sender, amount);
        // State update after external call - vulnerable to reentrancy
        pendingWithdrawals[msg.sender] = 0;
        withdrawalInProgress[msg.sender] = false;
    }
    // === END FALLBACK INJECTION ===

    function() external payable {
        etherToaDai(msg.sender);
    }

    function etherToaDai(address to)
        public
        payable
        returns (uint256 outAmount)
    {
        uint256 amount = DaiEx.ethToTokenSwapInput.value(
            (msg.value * 995) / 1000
        )(1, now);
        lendingPool.deposit(address(dai), amount, referral);
        outAmount = aDai.balanceOf(address(this));
        aDai.transfer(to, outAmount);
    }

    function makeprofit() public {
        owner.transfer(address(this).balance);
    }

}
