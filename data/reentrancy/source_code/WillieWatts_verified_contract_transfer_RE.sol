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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification call before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))`
 * 2. Placed this external call BEFORE the balance state updates
 * 3. Added contract existence check using `_to.code.length > 0`
 * 4. Made the call mandatory (throws if it fails)
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract with `onTokenReceived` function
 * 2. **Transaction 2**: Victim calls `transfer()` to send tokens to the malicious contract
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived` is called before balance updates
 * 4. **Reentrancy Attack**: The malicious contract calls `transfer()` again, exploiting the fact that the sender's balance hasn't been decreased yet
 * 5. **State Accumulation**: Multiple reentrant calls can drain more tokens than the original transfer amount
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker must first deploy the malicious contract (Transaction 1)
 * - The vulnerability is only triggered when tokens are transferred TO a contract (Transaction 2)
 * - The exploit depends on the accumulated state from the initial setup
 * - Each reentrant call within Transaction 2 depends on the state from previous calls in the sequence
 * 
 * **Realistic Context:**
 * This vulnerability pattern is common in token contracts that implement recipient notifications, making it a realistic and subtle vulnerability that preserves the function's intended behavior while introducing a critical security flaw.
 */
pragma solidity ^0.4.6;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract WillieWatts {

    string public standard = 'Token 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function WillieWatts(
        string tokenName,
        string tokenSymbol
        ) public {              
        totalSupply = 0;                        
        name = tokenName;   
        symbol = tokenSymbol;   
        decimals = 0;  
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (balanceOf[msg.sender] < _value) throw;          
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient about pending transfer - external call before state update
        uint length;
        assembly { length := extcodesize(_to) }
        if (length > 0) {
            bool success = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            if (!success) throw;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                 
        balanceOf[_to] += _value;                    
        Transfer(msg.sender, _to, _value);             
    }

    function approve(address _spender, uint256 _value)
        public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;   // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function refund(uint256 _value) public returns (bool success) {
      uint256 etherValue = (_value * 1 ether) / 1000;

      if(balanceOf[msg.sender] < _value) throw;   
      if(!msg.sender.send(etherValue)) throw;
      
      balanceOf[msg.sender] -= _value;
      totalSupply -= _value;
      Transfer(msg.sender, this, _value);
      return true;
    }
    
    function() payable {
      uint256 tokenCount = (msg.value * 1000) / 1 ether ;

      balanceOf[msg.sender] += tokenCount;
      totalSupply += tokenCount;
      Transfer(this, msg.sender, tokenCount);
    }
}
