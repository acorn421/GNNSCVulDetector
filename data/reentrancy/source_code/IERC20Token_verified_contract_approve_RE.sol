/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability where:
 * 
 * 1. **State Persistence**: Added `pendingApprovals` mapping that accumulates approval amounts across multiple transactions
 * 2. **External Call Before State Update**: Added external call to spender contract before updating allowance state
 * 3. **Accumulated State Dependency**: The vulnerability depends on `pendingApprovals` building up over multiple transactions to exceed the threshold
 * 4. **Multi-Transaction Exploitation**: 
 *    - Transaction 1-N: Attacker makes multiple approve() calls to accumulate pendingApprovals
 *    - During any external call, attacker can re-enter approve() to manipulate state
 *    - The threshold check (1000000 * 10**18) only triggers after accumulated state from multiple transactions
 *    - When threshold is reached, attacker gets double allowance bonus
 * 
 * **Multi-Transaction Exploitation Path:**
 * - Attacker needs multiple approve() calls to build up pendingApprovals state
 * - Each transaction adds to the cumulative counter
 * - Only when threshold is reached can the attacker exploit the double allowance bonus
 * - The reentrancy during external calls allows manipulation of the accumulated state
 * - Cannot be exploited in a single transaction due to the accumulation requirement
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability depends on `pendingApprovals` state accumulating across multiple transactions
 * - Single transaction cannot reach the threshold needed for exploitation
 * - The persistent state creates the vulnerability surface that grows with each transaction
 * - Reentrancy exploitation requires the accumulated state to be in a specific range to be effective
 */
pragma solidity ^0.4.15;

contract Owned {
    address public owner;
    address public newOwner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        assert(msg.sender == owner);
        _;
    }

    function transferOwnership(address _newOwner) public onlyOwner {
        require(_newOwner != owner);
        newOwner = _newOwner;
    }

    function acceptOwnership() public {
        require(msg.sender == newOwner);
        emit OwnerUpdate(owner, newOwner);
        owner = newOwner;
        newOwner = 0x0;
    }

    event OwnerUpdate(address _prevOwner, address _newOwner);
}

interface IApprovalReceiver {
    function onApprovalReceived(address owner, uint256 value) external;
}

contract IERC20Token {
    function totalSupply() public constant returns (uint256);
    function balanceOf(address _owner) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public pendingApprovals;

    function approve(address _spender, uint256 _value) public returns (bool success) {
        // Add to pending approvals for cumulative tracking
        pendingApprovals[msg.sender] += _value;

        // External call to spender contract for approval notification
        // This creates reentrancy opportunity
        if (isContract(_spender)) {
            IApprovalReceiver(_spender).onApprovalReceived(msg.sender, _value);
        }

        // State update happens AFTER external call (classic reentrancy pattern)
        allowance[msg.sender][_spender] = _value;

        // Check if cumulative pending approvals exceed threshold
        if (pendingApprovals[msg.sender] > 1000000 * 10**18) {
            // Reset pending approvals after threshold - this creates state dependency
            pendingApprovals[msg.sender] = 0;
            // Bonus allowance for high-volume approvers
            allowance[msg.sender][_spender] = _value * 2;
        }

        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}

contract VestingContract is Owned {

    address public withdrawalAddress;
    address public tokenAddress;

    uint public lastBlockClaimed;
    uint public blockDelay;
    uint public reward;

    event ClaimExecuted(uint _amount, uint _blockNumber, address _destination);

    constructor() public {
        lastBlockClaimed = 4315256;
        blockDelay = 5082;
        reward = 5000000000000000000000;
        tokenAddress = 0x2C974B2d0BA1716E644c1FC59982a89DDD2fF724;
    }

    function claimReward() public onlyOwner {
        require(block.number >= lastBlockClaimed + blockDelay);
        uint withdrawalAmount;
        if (IERC20Token(tokenAddress).balanceOf(address(this)) > reward) {
            withdrawalAmount = reward;
        } else {
            withdrawalAmount = IERC20Token(tokenAddress).balanceOf(address(this));
        }
        IERC20Token(tokenAddress).transfer(withdrawalAddress, withdrawalAmount);
        lastBlockClaimed += blockDelay;
        emit ClaimExecuted(withdrawalAmount, block.number, withdrawalAddress);
    }

    function salvageTokensFromContract(address _tokenAddress, address _to, uint _amount) public onlyOwner {
        require(_tokenAddress != tokenAddress);
        IERC20Token(_tokenAddress).transfer(_to, _amount);
    }

    //
    // Setters
    //
    function setWithdrawalAddress(address _newAddress) public onlyOwner {
        withdrawalAddress = _newAddress;
    }
    function setBlockDelay(uint _newBlockDelay) public onlyOwner {
        blockDelay = _newBlockDelay;
    }
    //
    // Getters
    //
    function getTokenBalance() public constant returns(uint) {
        return IERC20Token(tokenAddress).balanceOf(address(this));
    }
}
