/*
 * ===== SmartInject Injection Details =====
 * Function      : etherToaDai
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a pending withdrawal system. The vulnerability requires:
 * 
 * 1. **State Variables Added** (assumed to be added to contract):
 *    - `mapping(address => uint256) public pendingWithdrawals` - tracks pending withdrawals per user
 *    - `uint256 public totalPendingWithdrawals` - tracks total pending amount
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: User calls etherToaDai() when contract has insufficient aDai tokens, creating a pending withdrawal
 *    - **Transaction 2**: User calls etherToaDai() again with any ETH amount, triggering the vulnerable code path that processes pending withdrawals
 * 
 * 3. **Vulnerability Mechanism**:
 *    - When processing pending withdrawals, the external call `aDai.transfer(msg.sender, pendingAmount)` occurs BEFORE state updates
 *    - This allows the recipient contract to re-enter and call etherToaDai() again while `pendingWithdrawals[msg.sender]` is still non-zero
 *    - The attacker can drain multiple times the intended amount by repeatedly re-entering before the state is cleared
 * 
 * 4. **Multi-Transaction Requirement**:
 *    - The vulnerability cannot be exploited in a single transaction because pending withdrawals must be created first
 *    - Requires at least 2 transactions: one to create pending state, another to exploit the reentrancy during processing
 *    - State persists between transactions, enabling the exploitation sequence
 * 
 * 5. **Realistic Integration**:
 *    - The pending withdrawal mechanism appears as a legitimate feature to handle insufficient token scenarios
 *    - The vulnerability is subtle and could realistically appear in production code
 *    - Maintains all original functionality while adding the security flaw
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

    // === DECLARATIONS ADDED TO FIX ERRORS ===
    mapping(address => uint256) public pendingWithdrawals;
    uint256 public totalPendingWithdrawals;
    // === END DECLARATIONS ===

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if user has pending withdrawal from previous transactions
        if (pendingWithdrawals[msg.sender] > 0) {
            uint256 pendingAmount = pendingWithdrawals[msg.sender];
            // External call before state update - vulnerable to reentrancy
            aDai.transfer(msg.sender, pendingAmount);
            // State update after external call
            pendingWithdrawals[msg.sender] = 0;
            totalPendingWithdrawals -= pendingAmount;
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        uint256 amount = DaiEx.ethToTokenSwapInput.value(
            (msg.value * 995) / 1000
        )(1, now);
        lendingPool.deposit(address(dai), amount, referral);
        outAmount = aDai.balanceOf(address(this));
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Check if there are sufficient tokens for immediate transfer
        if (outAmount > totalPendingWithdrawals) {
            aDai.transfer(to, outAmount);
        } else {
            // If not enough tokens, add to pending withdrawals for next transaction
            pendingWithdrawals[to] += outAmount;
            totalPendingWithdrawals += outAmount;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function makeprofit() public {
        owner.transfer(address(this).balance);
    }
}
