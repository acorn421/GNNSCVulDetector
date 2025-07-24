/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Reordered State Updates**: Moved recipient balance update before the external call, creating an inconsistent state window where the recipient has received tokens but the sender's balance and allowance haven't been decremented yet.
 * 
 * 2. **Added External Call**: Inserted a call to `onTokenReceived` on the recipient contract if it's a contract address, creating a reentrancy opportunity.
 * 
 * 3. **Stateful Exploitation Pattern**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker sets up allowance and initiates first transfer
 *    - **Transaction 2**: During the external call, the attacker can re-enter `transferFrom` again, exploiting the inconsistent state where `balances[_to]` has been updated but `balances[_from]` and `allowed[_from][msg.sender]` haven't been decremented yet
 *    - **Transaction 3+**: Multiple re-entrant calls can drain the balance before the original state updates complete
 * 
 * 4. **Multi-Transaction Dependency**: The vulnerability cannot be exploited in a single transaction because:
 *    - Initial allowance must be set in a separate transaction via `approve()`
 *    - The reentrancy window only exists between the recipient balance update and the sender's balance/allowance updates
 *    - Multiple calls are needed to accumulate the benefit of the inconsistent state
 * 
 * 5. **Realistic Integration**: The `onTokenReceived` callback is a common pattern in modern token contracts (similar to ERC721/ERC1155 standards) making this vulnerability realistic and subtle.
 * 
 * The attacker contract would implement `onTokenReceived` to call back into `transferFrom` with the same parameters, potentially draining the approved amount multiple times before the original call completes its state updates.
 */
pragma solidity ^0.4.18;

contract ERC20Interface {
     // Get the total token supply
     function totalSupply() constant public returns (uint256 totalSupplyToken);
     // Get the account balance of another account with address _owner
     function balanceOf(address _owner) public constant returns (uint256 balance);

     // Send _value amount of tokens to address _to
     function transfer(address _to, uint256 _value) public returns (bool success);

     // Send _value amount of tokens from address _from to address _to
     function transferFrom (
          address _from,
          address _to,
         uint256 _amount
    ) public returns (bool success);

     // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
     // If this function is called again it overwrites the current allowance with _value.
     // this function is required for some DEX functionality
     function approve(address _spender, uint256 _value) public returns (bool success);

     // Returns the amount which _spender is still allowed to withdraw from _owner
     function allowance(address _owner, address _spender) public constant returns (uint256 remaining);

     // Triggered when tokens are transferred.
     event Transfer(address indexed _from, address indexed _to, uint256 _value);

     // Triggered whenever approve(address _spender, uint256 _value) is called.
     event Approval(address indexed _owner, address indexed _spender, uint256 _value);
 }

 contract FreelancerCoin is ERC20Interface {
     string public constant symbol = "LAN";
     string public constant name = "FreelancerCoin";
     uint8 public constant decimals = 18;
     uint256 _totalSupply = 80000000000000000000000000;

     // Owner of this contract
     address public owner;

     // Balances for each account
     mapping(address => uint256) balances;

     // Owner of account approves the transfer of an amount to another account
     mapping(address => mapping (address => uint256)) allowed;

     // Functions with this modifier can only be executed by the owner
     modifier onlyOwner() {
         require(msg.sender != owner);
         _;
      }

      // Constructor
      constructor() public {
          owner = msg.sender;
          balances[owner] = _totalSupply;
      }
     function totalSupply() constant public returns (uint256 totalSupplyToken) {
         totalSupplyToken = _totalSupply;
     }
      // What is the balance of a particular account?
      function balanceOf(address _owner) public constant returns (uint256 balance) {
         return balances[_owner];
      }

      // Transfer the balance from owner's account to another account
      function transfer(address _to, uint256 _amount) public returns (bool success) {
         if (balances[msg.sender] >= _amount
              && _amount > 0
              && balances[_to] + _amount > balances[_to]) {
              balances[msg.sender] -= _amount;
              balances[_to] += _amount;
              Transfer(msg.sender, _to, _amount);
              return true;
          } else {
              return false;
         }
      }

      // Send _value amount of tokens from address _from to address _to
      // The transferFrom method is used for a withdraw workflow, allowing contracts to send
      // tokens on your behalf, for example to "deposit" to a contract address and/or to charge
      // fees in sub-currencies; the command should fail unless the _from account has
      // deliberately authorized the sender of the message via some mechanism; we propose
      // these standardized APIs for approval:
      function transferFrom (
          address _from,
          address _to,
         uint256 _amount
    ) public returns (bool success) {
       if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
           && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
           // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
           // Update recipient balance first to enable notification
           balances[_to] += _amount;
           // Notify recipient contract of incoming transfer (external call before state cleanup)
           if (isContract(_to)) {
               (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _amount));
               require(callSuccess, "Transfer notification failed");
           }
           // Complete state updates after external call
           // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
           balances[_from] -= _amount;
           allowed[_from][msg.sender] -= _amount;
           // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
           Transfer(_from, _to, _amount);
           return true;
           // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        } else {
            return false;
         }
     }

    // Helper to detect contract
    function isContract(address _addr) internal view returns (bool) {
        uint codeLength;
        assembly { codeLength := extcodesize(_addr) }
        return codeLength > 0;
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
     // If this function is called again it overwrites the current allowance with _value.
     function approve(address _spender, uint256 _amount) public returns (bool success) {
         allowed[msg.sender][_spender] = _amount;
         Approval(msg.sender, _spender, _amount);
         return true;
     }

     function allowance(address _owner, address _spender) constant public returns (uint256 remaining) {
         return allowed[_owner][_spender];
     }
}
