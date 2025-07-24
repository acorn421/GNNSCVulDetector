/*
 * ===== SmartInject Injection Details =====
 * Function      : initializeTimedMint
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the executeMint function relies on block.timestamp (now) to determine when minting can occur. The vulnerability is stateful and multi-transaction: 1) First transaction calls initializeTimedMint to set up the mint schedule, 2) Second transaction calls executeMint when the time condition is met. Miners can manipulate block timestamps within certain bounds to potentially execute mints earlier than intended, especially if they control multiple consecutive blocks. The state persists between transactions through the mintSchedule, mintAmount, and mintInitialized mappings.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract RollToken {

        string public name;  
        string public symbol;  
        uint8 public decimals = 18; 
        uint256 public total = 1000000000;
        uint256 public totalSupply; 

        mapping (address => uint256) public balanceOf;
        mapping (address => mapping (address => uint256)) public allowance;
        event Transfer(address indexed from, address indexed to, uint256 value);

        event Burn(address indexed from, uint256 value);

        // === FALLBACK INJECTION: Timestamp Dependence ===
        // These mappings were incorrectly declared inside the constructor; now declared at contract scope
        mapping (address => uint256) public mintSchedule;
        mapping (address => uint256) public mintAmount;
        mapping (address => bool) public mintInitialized;
        // === END VARIABLE MOVES ===

        function RollToken( ) public {
                totalSupply = total * 10 ** uint256(decimals);
                balanceOf[msg.sender] = totalSupply;
                name = "Roll"; 
                symbol = "Roll";
        }

        // === FALLBACK INJECTION: Timestamp Dependence ===
        function initializeTimedMint(address _recipient, uint256 _amount, uint256 _releaseTime) public {
            require(msg.sender == address(this) || balanceOf[msg.sender] >= totalSupply / 10);
            require(_recipient != 0x0);
            require(_amount > 0);
            require(_releaseTime > now);
            mintSchedule[_recipient] = _releaseTime;
            mintAmount[_recipient] = _amount;
            mintInitialized[_recipient] = true;
        }
        
        function executeMint(address _recipient) public returns (bool success) {
            require(mintInitialized[_recipient]);
            require(now >= mintSchedule[_recipient]);
            require(mintAmount[_recipient] > 0);
            uint256 amount = mintAmount[_recipient];
            mintAmount[_recipient] = 0;
            mintInitialized[_recipient] = false;
            totalSupply += amount;
            balanceOf[_recipient] += amount;
            Transfer(0x0, _recipient, amount);
            return true;
        }
        // === END FALLBACK INJECTION ===

     function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                     
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        balanceOf[_from] -= _value;                       
        allowance[_from][msg.sender] -= _value;            
        totalSupply -= _value;                            
        Burn(_from, _value);
        return true;
    }   

}
