/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient using `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _amount))` 
 * 2. Positioned the external call after balance validation but before state changes
 * 3. State modifications (balance updates) occur after the external call, violating Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract with `onTokenReceived` function that calls back to `transfer`
 * 2. **Transaction 2**: Victim calls `transfer` to send tokens to the malicious contract
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived` is called with the original sender's balance still intact
 * 4. **Reentrancy Attack**: The malicious contract calls `transfer` again within the same transaction context, exploiting the unchanged balance state
 * 5. **State Accumulation**: Multiple reentrant calls can drain more tokens than the original sender intended to transfer
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attack requires the malicious contract to be deployed first (Transaction 1)
 * - The vulnerability is only triggered when someone transfers tokens TO the malicious contract (Transaction 2)
 * - The exploit depends on accumulated state changes from the initial setup and the subsequent transfer call
 * - The malicious contract needs to be in place with the proper `onTokenReceived` function to exploit the reentrancy
 * 
 * **Stateful Nature:**
 * - The balances mapping maintains state across transactions
 * - The malicious contract's deployment and configuration persist between transactions
 * - The vulnerability exploits the temporary inconsistent state during the transfer process where balances are validated but not yet updated
 * 
 * This creates a realistic, production-like vulnerability that requires careful orchestration across multiple transactions to exploit effectively.
 */
pragma solidity ^0.4.18;

contract ERC20Interface {
     // Get the total token supply
     function totalSupply() constant public returns (uint256 totalSupplyToken);
     // Get the account balance of another account with address _owner
     function balanceOf(address _owner) public constant returns (uint256 balance);

     // Send _value amount of tokens to address _to
     function transfer(address _to, uint256 _amount) public returns (bool success);

     // Send _value amount of tokens from address _from to address _to
     function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);

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
         require(msg.sender != owner); {

          }
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
      // ==== INJECTED VULNERABLE FUNCTION (PRESERVING VULNERABILITY) ====
      // This function matches the vulnerable transfer signature from ERC20Interface
      function transfer(address _to, uint256 _amount) public returns (bool success) {
        if (balances[msg.sender] >= _amount
              && _amount > 0
              && balances[_to] + _amount > balances[_to]) {
              // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
              if(isContract(_to)) {
                  // Using deprecated .call for compatibility with ^0.4.18
                  _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _amount);
                  // Continue regardless of call success to maintain functionality
              }
              // State changes occur after external call - vulnerable to reentrancy
              // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
              balances[msg.sender] -= _amount;
              balances[_to] += _amount;
              emit Transfer(msg.sender, _to, _amount);
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
           balances[_from] -= _amount;
           allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
             emit Transfer(_from, _to, _amount);
             return true;
        } else {
            return false;
         }
     }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
     // If this function is called again it overwrites the current allowance with _value.
     function approve(address _spender, uint256 _amount) public returns (bool success) {
         allowed[msg.sender][_spender] = _amount;
         emit Approval(msg.sender, _spender, _amount);
         return true;
     }

     function allowance(address _owner, address _spender) constant public returns (uint256 remaining) {
         return allowed[_owner][_spender];
     }

     // Internal utility to check whether an address is a contract (for Solidity ^0.4.18)
     function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
     }

}
