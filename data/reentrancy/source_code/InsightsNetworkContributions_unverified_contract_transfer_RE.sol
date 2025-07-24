/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a two-phase transfer system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Phase 1 (Transaction 1)**: Owner calls transfer() to initiate a transfer, setting transferInitiated[recipient] = true and pendingTransfers[recipient] = amount.
 * 
 * **Phase 2 (Transaction 2)**: Owner calls transfer() again to complete the transfer. This is where the vulnerability exists - the external call recipient.transfer(transferAmount) happens before the state cleanup (pendingTransfers[recipient] = 0).
 * 
 * **Multi-Transaction Exploitation**:
 * 1. Attacker deploys a malicious contract as the recipient
 * 2. Owner initiates transfer to attacker's contract (Transaction 1)
 * 3. Owner completes transfer to attacker's contract (Transaction 2)
 * 4. During the recipient.transfer() call, the attacker's contract re-enters the transfer function
 * 5. Since pendingTransfers[recipient] is still > 0 and transferInitiated[recipient] is still true, the attacker can trigger multiple transfers before the state is cleaned up
 * 6. Each reentrant call executes the transfer again, draining more funds than intended
 * 
 * **Why Multi-Transaction is Required**:
 * - The vulnerability cannot be exploited in a single transaction because the first call only sets up the pending transfer state
 * - The external call (and thus reentrancy opportunity) only occurs in the second transaction
 * - The attacker needs the persistent state from the first transaction to enable the vulnerability in the second transaction
 * - This creates a realistic time-gap vulnerability where state persists between transactions, allowing for more sophisticated attack scenarios
 */
pragma solidity ^0.4.18;

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;


  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
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
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}

contract InsightsNetworkContributions is Ownable {

    string public name;
    uint256 public cap;
    uint256 public contributionMinimum;
    uint256 public contributionMaximum;
    uint256 public gasPriceMaximum;

    bool enabled;
    uint256 total;

    mapping (address => bool) public registered;
    mapping (address => uint256) public balances;

    event Approval(address indexed account, bool valid);
    event Contribution(address indexed contributor, uint256 amount);
    event Transfer(address indexed recipient, uint256 amount, address owner);

    function InsightsNetworkContributions(string _name, uint256 _cap, uint256 _contributionMinimum, uint256 _contributionMaximum, uint256 _gasPriceMaximum) public {
        require(_contributionMinimum <= _contributionMaximum);
        require(_contributionMaximum > 0);
        require(_contributionMaximum <= _cap);
        name = _name;
        cap = _cap;
        contributionMinimum = _contributionMinimum;
        contributionMaximum = _contributionMaximum;
        gasPriceMaximum = _gasPriceMaximum;
        enabled = false;
    }

    function () external payable {
        contribute();
    }

    function contribute() public payable {
        require(enabled);
        require(tx.gasprice <= gasPriceMaximum);
        address sender = msg.sender;
        require(registered[sender]);
        uint256 value = msg.value;
        uint256 balance = balances[sender] + value;
        require(balance >= contributionMinimum);
        require(balance <= contributionMaximum);
        require(total + value <= cap);
        balances[sender] = balance;
        total += value;
        Contribution(sender, value);
    }

    function enable(bool _enabled) public onlyOwner {
        enabled = _enabled;
    }

    function register(address account, bool valid) public onlyOwner {
        require(account != 0);
        registered[account] = valid;
        Approval(account, valid);
    }

    function registerMultiple(address[] accounts, bool valid) public onlyOwner {
        require(accounts.length <= 128);
        for (uint index = 0; index < accounts.length; index++) {
            address account = accounts[index];
            require(account != 0);
            registered[account] = valid;
            Approval(account, valid);
        }
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingTransfers;
    mapping(address => bool) public transferInitiated;
    
    function transfer(address recipient, uint256 amount) public onlyOwner {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        require(recipient != 0);
        require(amount <= this.balance);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        if (!transferInitiated[recipient]) {
            // First transaction: initiate transfer
            transferInitiated[recipient] = true;
            pendingTransfers[recipient] = amount;
            Transfer(recipient, amount, owner);
        } else {
            // Second transaction: complete transfer
            require(pendingTransfers[recipient] > 0);
            uint256 transferAmount = pendingTransfers[recipient];
            require(transferAmount <= this.balance);
            
            // Vulnerable: external call before state cleanup
            recipient.transfer(transferAmount);
            
            // State cleanup after external call - reentrancy window
            pendingTransfers[recipient] = 0;
            transferInitiated[recipient] = false;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function selfDestruct() public onlyOwner {
        require(!enabled);
        require(this.balance == 0);
        selfdestruct(owner);
    }

}