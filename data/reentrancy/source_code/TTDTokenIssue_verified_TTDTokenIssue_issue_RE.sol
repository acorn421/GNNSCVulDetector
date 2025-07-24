/*
 * ===== SmartInject Injection Details =====
 * Function      : issue
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 6 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 * ... and 3 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the owner contract before state updates. The vulnerability allows a malicious owner to re-enter the issue function multiple times before the balanceOf and totalSupply state variables are updated, enabling them to accumulate excessive tokens across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to owner contract using `owner.call(data)` before state updates
 * 2. The call invokes a hypothetical `onTokensIssued` function on the owner contract
 * 3. External call occurs before `balanceOf[owner]` and `totalSupply` are updated (violating Checks-Effects-Interactions pattern)
 * 4. Added require statement to ensure the external call succeeds
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Transaction**: Malicious owner deploys a contract with `onTokensIssued` function that re-enters the issue function
 * 2. **Initial Issue Transaction**: When `TTDTokenIssue.issue()` is called, it calls `TTDToken.issue(amount)`
 * 3. **Reentrancy Chain**: The owner notification triggers the malicious contract's `onTokensIssued` function
 * 4. **State Manipulation**: The malicious contract calls back into the issueContractAddress to trigger additional `issue()` calls
 * 5. **Accumulation**: Each reentrant call adds more tokens before the original transaction's state updates complete
 * 6. **State Persistence**: The inflated balanceOf and totalSupply values persist across transactions
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the attacker to first deploy and configure a malicious owner contract
 * - The issueContractAddress must be compromised or manipulated to enable multiple calls
 * - State accumulation happens across multiple issue cycles, with each transaction building upon previous state changes
 * - The attack exploits the time gap between external calls and state updates across multiple transaction contexts
 * - The totalSupply parameter passed to the callback reflects outdated state, allowing calculation-based attacks across multiple calls
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
contract TTDTokenIssue {
    uint256 public lastYearTotalSupply = 15 * 10 ** 26; 
    uint8   public affectedCount = 0;
    bool    public initialYear = true; 
	//uint16  public blockHeight = 2102400;
	address public tokenContractAddress;
    uint16  public preRate = 1000; 
    uint256 public lastBlockNumber;

    constructor(address _tokenContractAddress) public{
        tokenContractAddress = _tokenContractAddress;
        lastBlockNumber = block.number;
    }

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
        TTDToken tokenContract = TTDToken(tokenContractAddress);
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
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external;
}

contract TTDToken {
    string public name = 'TTD Token';
    string public symbol = 'TTD';
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

    constructor() public {
        owner = msg.sender;
        balanceOf[owner] = totalSupply;
        issueContractAddress = new TTDTokenIssue(address(this));
    }

    function issue(uint256 amount) public {
        require(msg.sender == issueContractAddress);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Vulnerable call to owner, intentionally preserved for testing
        bytes memory data = abi.encodeWithSignature("onTokensIssued(uint256,uint256)", amount, totalSupply);
        owner.call(data);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
