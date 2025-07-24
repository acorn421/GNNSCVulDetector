/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to an approval oracle before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: Attacker deploys a malicious oracle contract and calls a function to set it as the approvalOracle
 * 2. **Transaction 2**: Attacker calls approve() with their malicious oracle, which re-enters the approve function during the external call
 * 3. **Transaction 3+**: The attacker exploits the inconsistent state created by the reentrancy
 * 
 * The vulnerability is stateful because:
 * - It relies on the approvalOracle being set in a previous transaction
 * - The approvalCount and isApprovalLocked mappings persist between transactions
 * - The exploit requires accumulated state from multiple approve calls
 * 
 * The reentrancy occurs when the external call to approvalOracle happens before the state variables (allowance, approvalCount, totalApprovals) are updated. During the external call, the oracle can re-enter the approve function with the old state still intact, allowing it to bypass the approval locking mechanism or create double-spending scenarios.
 * 
 * Multi-transaction exploitation scenario:
 * 1. First transaction: Set malicious oracle contract
 * 2. Second transaction: Call approve() multiple times through reentrancy to bypass the 10-approval limit
 * 3. Third transaction: Exploit the excessive approvals that shouldn't have been possible
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

interface IApprovalOracle {
    function notifyApproval(address owner, address spender, uint256 value) external;
}

contract Erc20 {
    function balanceOf(address _owner) public view returns (uint256);
    function transfer(address _to, uint256 _value) public returns (bool);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => mapping(address => uint256)) public allowance;
mapping(address => uint256) public approvalCount;
mapping(address => bool) public isApprovalLocked;
address public approvalOracle;
uint256 public totalApprovals;

function approve(address _spender, uint256 _value) public returns (bool) {
    // Check if approvals are locked for this user
    require(!isApprovalLocked[msg.sender], "Approvals locked");
    
    // External call to oracle before state updates (reentrancy vulnerability)
    if (approvalOracle != address(0)) {
        // This external call can trigger reentrancy
        IApprovalOracle(approvalOracle).notifyApproval(msg.sender, _spender, _value);
    }
    
    // State updates happen after external call - vulnerable to reentrancy
    allowance[msg.sender][_spender] = _value;
    approvalCount[msg.sender]++;
    totalApprovals++;
    
    // Lock approvals if user has made too many approvals
    if (approvalCount[msg.sender] >= 10) {
        isApprovalLocked[msg.sender] = true;
    }
    
    return true;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}
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
        owner.transfer(address(this).balance);
    }

}
