/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTradingWindow
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
 * This injection introduces a stateful, multi-transaction timestamp dependence vulnerability. The vulnerability manifests through: 1) initiateTradingWindow() uses block.timestamp to set trading window boundaries, which miners can manipulate, 2) privilegedTrade() depends on these timestamp-based state variables across multiple transactions, 3) The exploitation requires multiple function calls: first initiateTradingWindow() to set vulnerable state, then multiple privilegedTrade() calls to exploit the manipulated timestamps, 4) State persists between transactions through tradingWindowStart, tradingWindowEnd, and tradingWindowActive variables, making this a true multi-transaction vulnerability that cannot be exploited in a single transaction.
 */
pragma solidity ^0.4.24;

contract ERC20TokenSAC {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    address public cfoOfTokenSAC;
    
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => bool) public frozenAccount;
    
    event Transfer (address indexed from, address indexed to, uint256 value);
    event Approval (address indexed owner, address indexed spender, uint256 value);
    event MintToken (address to, uint256 mintvalue);
    event MeltToken (address from, uint256 meltvalue);
    event FreezeEvent (address target, bool result);
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Trading window state variables
    uint256 public tradingWindowStart;
    uint256 public tradingWindowEnd;
    bool public tradingWindowActive;
    uint256 public tradingWindowDuration = 1 hours;
    
    // State tracking for multi-transaction vulnerability
    mapping(address => uint256) public lastTradingWindowParticipation;
    uint256 public totalTradingWindowVolume;
    
    event TradingWindowOpened(uint256 startTime, uint256 endTime);
    event TradingWindowClosed(uint256 totalVolume);

    constructor (
        uint256 initialSupply,
        string memory tokenName,
        string memory tokenSymbol
        ) public {
        cfoOfTokenSAC = msg.sender;
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }

    /**
     * @dev Initiates a new trading window - vulnerable to timestamp manipulation
     * This function creates a stateful vulnerability that requires multiple transactions
     * to fully exploit. Miners can manipulate timestamps to extend or control trading windows.
     */
    function initiateTradingWindow() onlycfo public returns (bool) {
        require(!tradingWindowActive, "Trading window already active");
        
        // VULNERABILITY: Using block.timestamp for time-sensitive operations
        // Miners can manipulate timestamp within ~900 seconds
        tradingWindowStart = block.timestamp;
        tradingWindowEnd = block.timestamp + tradingWindowDuration;
        tradingWindowActive = true;
        totalTradingWindowVolume = 0;
        
        emit TradingWindowOpened(tradingWindowStart, tradingWindowEnd);
        return true;
    }
    
    /**
     * @dev Allows privileged trading during active window - stateful vulnerability
     * This function depends on the timestamp-dependent trading window state
     */
    function privilegedTrade(address to, uint256 amount) public returns (bool) {
        require(tradingWindowActive, "No active trading window");
        require(block.timestamp >= tradingWindowStart && block.timestamp <= tradingWindowEnd, "Outside trading window");
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        
        // Track participation for multi-transaction exploitation
        lastTradingWindowParticipation[msg.sender] = block.timestamp;
        totalTradingWindowVolume += amount;
        
        // Perform the trade with reduced fees or special privileges
        _transfer(msg.sender, to, amount);
        
        // Auto-close window if volume threshold reached (another state dependency)
        if (totalTradingWindowVolume >= totalSupply / 10) {
            tradingWindowActive = false;
            emit TradingWindowClosed(totalTradingWindowVolume);
        }
        
        return true;
    }
    
    /**
     * @dev Manually close trading window - completes the stateful vulnerability chain
     */
    function closeTradingWindow() onlycfo public returns (bool) {
        require(tradingWindowActive, "No active trading window");
        require(block.timestamp > tradingWindowEnd, "Trading window still active");
        
        tradingWindowActive = false;
        emit TradingWindowClosed(totalTradingWindowVolume);
        return true;
    }
    // === END FALLBACK INJECTION ===

    modifier onlycfo {
        require (msg.sender == cfoOfTokenSAC);
        _;
    }
    
    function _transfer (address _from, address _to, uint _value) internal {
        require (!frozenAccount[_from]);
        require (!frozenAccount[_to]);
        require (_to != address(0x0));
        require (balanceOf[_from] >= _value);
        require (balanceOf[_to] + _value >= balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer (_from, _to, _value);
        assert (balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
    
    function transfer (address _to, uint256 _value) public returns (bool success) {
        _transfer (msg.sender, _to, _value);
        return true;
    }
    
    function transferFrom (address _from, address _to, uint256 _value) public returns (bool success) {
        require (_value <= allowance[_from][msg.sender]);
        _transfer (_from, _to, _value);
        allowance[_from][msg.sender] -= _value;
        return true;
    }
    
    function approve (address _spender, uint256 _value) public returns (bool success) {
        require (_spender != address(0x0));
        require (_value != 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval (msg.sender, _spender, _value);
        return true;
    }
    
    function appointNewcfo (address newcfo) onlycfo public returns (bool) {
        require (newcfo != cfoOfTokenSAC);
        cfoOfTokenSAC = newcfo;
        return true;
    }
    
    function mintToken (address target, uint256 amount) onlycfo public returns (bool) {
        require (target != address(0x0));
        require (amount != 0);
        balanceOf[target] += amount;
        totalSupply += amount;
        emit MintToken (target, amount);
        return true;
    }
    
    function meltToken (address target, uint256 amount) onlycfo public returns (bool) {
        require (target != address(0x0));
        require (amount <= balanceOf[target]);
        require (amount != 0);
        balanceOf[target] -= amount;
        totalSupply -= amount;
        emit MeltToken (target, amount);
        return true;
    }
    
    function freezeAccount (address target, bool freeze) onlycfo public returns (bool) {
        require (target != address(0x0));
        frozenAccount[target] = freeze;
        emit FreezeEvent (target, freeze);
        return true;
    }
}
