/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient's receiveApproval function after balance updates but before allowance reduction. This creates a reentrancy window where the allowance hasn't been decremented yet, allowing a malicious contract to:
 * 
 * 1. **Transaction 1**: Initial transferFrom call that triggers the callback during which the malicious contract can call transferFrom again using the same allowance (since it hasn't been decremented yet)
 * 2. **Transaction 2**: Follow-up transfers that drain more funds using the accumulated state changes from the first transaction
 * 3. **Multi-Transaction Accumulation**: The vulnerability can be triggered across multiple transactions where each call potentially allows additional unauthorized transfers
 * 
 * The vulnerability is stateful because:
 * - The allowance state persists between transactions
 * - Balance changes from previous transactions affect subsequent exploitation
 * - The vulnerability requires building up state across multiple function calls rather than being exploitable in a single atomic transaction
 * 
 * This pattern is realistic as it mimics notification systems commonly added to token contracts, making it a subtle but dangerous vulnerability.
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
        balanceOf[msg.sender] -= _value;                 
        balanceOf[_to] += _value;                    
        Transfer(msg.sender, _to, _value);             
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient about the transfer - VULNERABILITY: External call before allowance update
        if (_to != address(0) && _to != msg.sender && _to != address(this)) {
            uint256 codeLength;
            assembly { codeLength := extcodesize(_to) }
            if(codeLength > 0) {
                tokenRecipient(_to).receiveApproval(_from, _value, this, "");
            }
        }
        allowance[_from][msg.sender] -= _value;              // VULNERABLE: State update after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
