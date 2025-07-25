/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimedMinting
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through a two-step minting process. First, enableTimedMinting() sets up a delayed minting operation with a specific timestamp. Then, executeTimedMinting() can only be called after that timestamp. The vulnerability allows miners to manipulate block.timestamp within reasonable bounds (up to 900 seconds in the future) to either delay or accelerate the minting execution. This is a stateful vulnerability requiring multiple transactions: one to enable the timed minting and another to execute it, with persistent state stored between calls.
 */
pragma solidity ^0.4.18;

library SafeOpt {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b > 0); 
        uint256 c = a / b;
        assert(a == b * c);
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a - b;
        assert(b <= a);
        assert(a == c + b);
        return c;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        assert(a == c - b);
        return c;
    }
}
contract TTBTokenIssue {
    uint256 public lastYearTotalSupply = 15 * 10 ** 26; 
    uint8   public affectedCount = 0;
    bool    public initialYear = true; 
    address public tokenContractAddress;
    uint16  public preRate = 1000; 
    uint256 public lastBlockNumber;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These variables were previously declared inside constructor, which is invalid in Solidity <0.6
    uint256 public timedMintingStartTime;
    uint256 public timedMintingAmount;
    bool public timedMintingActive = false;
    address public owner;

    event Issue(uint256 amount);

    function TTBTokenIssue (address _tokenContractAddress) public {
        owner = msg.sender;
        tokenContractAddress = _tokenContractAddress;
        lastBlockNumber = block.number;
    }

    function enableTimedMinting(uint256 _amount, uint256 _delay) public {
        require(msg.sender == owner);
        require(!timedMintingActive);
        timedMintingStartTime = block.timestamp + _delay;
        timedMintingAmount = _amount;
        timedMintingActive = true;
    }
    
    function executeTimedMinting() public {
        require(timedMintingActive);
        require(block.timestamp >= timedMintingStartTime);
        
        // Vulnerability: Using block.timestamp for critical operations
        // Miners can manipulate timestamp within reasonable bounds
        TTBToken tokenContract = TTBToken(tokenContractAddress);
        tokenContract.balanceOf(owner); // ensure balanceOf function exists
        // Use delegate call to update balanceOf and totalSupply
        // But since TTBToken is separate, and balanceOf and totalSupply don't exist in TTBTokenIssue, add mapping and variable for them
        balanceOf[owner] = SafeOpt.add(balanceOf[owner], timedMintingAmount);
        totalSupply = SafeOpt.add(totalSupply, timedMintingAmount);

        timedMintingActive = false;
        Issue(timedMintingAmount);
    }
    // === END FALLBACK INJECTION ===

    // The following are needed to prevent reference errors in the injected code:
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function returnRate() internal returns (uint256){
        if(affectedCount == 10){
            if(preRate > 100){
                preRate -= 100;
            }
            affectedCount = 0;
        }
        return SafeOpt.div(preRate, 10);
    }

    function issue() public  {
        if(initialYear){
            require(SafeOpt.sub(block.number, lastBlockNumber) > 2102400);
            initialYear = false;
        }
        require(SafeOpt.sub(block.number, lastBlockNumber) > 2102400);
        TTBToken tokenContract = TTBToken(tokenContractAddress);
        if(affectedCount == 10){
            lastYearTotalSupply = tokenContract.totalSupply();
        }
        uint256 amount = SafeOpt.div(SafeOpt.mul(lastYearTotalSupply, returnRate()), 10000);
        require(amount > 0);
        tokenContract.issue(amount);
        lastBlockNumber = block.number;
        affectedCount += 1;
    }
}


interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public;
}

contract TTBToken {
    string public name = 'Tip-Top Block';
    string public symbol = 'TTB';
    uint8 public decimals = 18;
    uint256 public totalSupply = 100 * 10 ** 26;

    address public issueContractAddress;
    address public owner;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Burn(address indexed from, uint256 value);
    event Issue(uint256 amount);

    function TTBToken() public {
        owner = msg.sender;
        balanceOf[owner] = totalSupply;
        issueContractAddress = new TTBTokenIssue(address(this));
    }

    function issue(uint256 amount) public {
        require(msg.sender == issueContractAddress);
        balanceOf[owner] = SafeOpt.add(balanceOf[owner], amount);
        totalSupply = SafeOpt.add(totalSupply, amount);
        Issue(amount);
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balanceOf[_owner];
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public returns (bool success){
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_value <= balanceOf[msg.sender]);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function allowance(address _owner, address _spender) view public returns (uint256 remaining) {
        return allowance[_owner][_spender];
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
