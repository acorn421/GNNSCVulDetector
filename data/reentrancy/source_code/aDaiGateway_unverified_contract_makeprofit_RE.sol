/*
 * ===== SmartInject Injection Details =====
 * Function      : makeprofit
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding withdrawal state tracking variables (withdrawalInProgress, pendingWithdrawal, totalWithdrawn) that persist across transactions. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: Owner calls makeprofit() - sets withdrawalInProgress=true, calculates pendingWithdrawal amount
 * 2. **Transaction 2**: During owner.transfer() call, if owner is a malicious contract, it can re-enter makeprofit() 
 * 3. **Exploitation**: The re-entrant call bypasses the withdrawalInProgress check because state updates happen after the external call, allowing multiple withdrawals before state is properly updated
 * 
 * The vulnerability is multi-transaction because:
 * - Initial state setup requires one transaction to set withdrawalInProgress=true
 * - The actual exploitation happens during the external call in a subsequent transaction context
 * - State variables (totalWithdrawn, pendingWithdrawal) accumulate across multiple calls
 * - The vulnerability cannot be exploited in a single atomic transaction without the state persistence
 * 
 * This creates a realistic cross-transaction reentrancy where the attacker must first trigger the withdrawal process, then exploit the reentrancy during the transfer execution, making it a genuine multi-transaction vulnerability.
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

    // === Added state variables for makeprofit vulnerabilities ===
    bool private withdrawalInProgress;
    uint256 private pendingWithdrawal;
    uint256 public totalWithdrawn;

    constructor() public {
        dai.approve(0x3dfd23A6c5E8BbcFc9581d2E864a68feb6a076d3, uint256(-1)); //lendingPoolCore
    }

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require(msg.sender == owner, "Only owner can make profit");
        
        // Add state tracking for withdrawal process
        if (!withdrawalInProgress) {
            withdrawalInProgress = true;
            pendingWithdrawal = address(this).balance;
            
            // External call before state update - reentrancy vector
            owner.transfer(pendingWithdrawal);
            
            // State update after external call - vulnerable pattern
            totalWithdrawn += pendingWithdrawal;
            withdrawalInProgress = false;
            pendingWithdrawal = 0;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}