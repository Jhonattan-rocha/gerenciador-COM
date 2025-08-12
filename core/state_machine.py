import threading
import time
import logging
from typing import Optional, Dict, Any, Callable, Set
from enum import Enum, auto
from dataclasses import dataclass
from collections import defaultdict


class AgentState(Enum):
    """Agent states."""
    INITIALIZING = auto()
    IDLE = auto()
    CONNECTING_SERIAL = auto()
    SERIAL_CONNECTED = auto()
    CONNECTING_NETWORK = auto()
    NETWORK_CONNECTED = auto()
    FULLY_CONNECTED = auto()
    TRANSMITTING = auto()
    ERROR = auto()
    RECONNECTING = auto()
    SHUTTING_DOWN = auto()
    SHUTDOWN = auto()


class AgentEvent(Enum):
    """Agent events that trigger state transitions."""
    START = auto()
    SERIAL_CONNECT_REQUEST = auto()
    SERIAL_CONNECTED = auto()
    SERIAL_DISCONNECTED = auto()
    SERIAL_ERROR = auto()
    NETWORK_CONNECT_REQUEST = auto()
    NETWORK_CONNECTED = auto()
    NETWORK_DISCONNECTED = auto()
    NETWORK_ERROR = auto()
    DATA_RECEIVED = auto()
    DATA_SENT = auto()
    TRANSMISSION_COMPLETE = auto()
    RECONNECT_REQUEST = auto()
    RECONNECT_SUCCESS = auto()
    RECONNECT_FAILED = auto()
    SHUTDOWN_REQUEST = auto()
    ERROR_OCCURRED = auto()
    RESET_REQUEST = auto()


@dataclass
class StateTransition:
    """Represents a state transition."""
    from_state: AgentState
    event: AgentEvent
    to_state: AgentState
    condition: Optional[Callable[[], bool]] = None
    action: Optional[Callable[[], None]] = None


@dataclass
class StateInfo:
    """Information about current state."""
    state: AgentState
    entered_at: float
    previous_state: Optional[AgentState] = None
    metadata: Dict[str, Any] = None


class AgentStateMachine:
    """Thread-safe state machine for agent lifecycle management."""
    
    def __init__(self, 
                 state_callback: Optional[Callable[[StateInfo], None]] = None,
                 transition_callback: Optional[Callable[[AgentState, AgentEvent, AgentState], None]] = None):
        self.state_callback = state_callback
        self.transition_callback = transition_callback
        
        # Current state
        self._current_state = AgentState.INITIALIZING
        self._state_info = StateInfo(
            state=self._current_state,
            entered_at=time.time(),
            metadata={}
        )
        
        # Threading
        self._lock = threading.RLock()
        
        # State transitions
        self._transitions: Dict[tuple[AgentState, AgentEvent], StateTransition] = {}
        self._state_handlers: Dict[AgentState, Callable[[StateInfo], None]] = {}
        self._event_queue = []
        self._processing_events = False
        
        # Statistics
        self._state_history = []
        self._transition_count = defaultdict(int)
        self._state_durations = defaultdict(list)
        
        self.logger = logging.getLogger("AgentStateMachine")
        
        # Initialize state machine
        self._setup_transitions()
        self._setup_state_handlers()
    
    def get_current_state(self) -> StateInfo:
        """Get current state information."""
        with self._lock:
            return StateInfo(
                state=self._current_state,
                entered_at=self._state_info.entered_at,
                previous_state=self._state_info.previous_state,
                metadata=self._state_info.metadata.copy() if self._state_info.metadata else {}
            )
    
    def trigger_event(self, event: AgentEvent, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Trigger an event to potentially cause a state transition."""
        with self._lock:
            self.logger.debug(f"Event triggered: {event.name} in state {self._current_state.name}")
            
            # Add event to queue
            self._event_queue.append((event, metadata or {}))
            
            # Process events if not already processing
            if not self._processing_events:
                self._process_event_queue()
            
            return True
    
    def can_transition(self, event: AgentEvent) -> bool:
        """Check if a transition is possible for the given event."""
        with self._lock:
            transition_key = (self._current_state, event)
            return transition_key in self._transitions
    
    def get_valid_events(self) -> Set[AgentEvent]:
        """Get valid events for current state."""
        with self._lock:
            valid_events = set()
            for (state, event) in self._transitions.keys():
                if state == self._current_state:
                    valid_events.add(event)
            return valid_events
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get state machine statistics."""
        with self._lock:
            current_time = time.time()
            current_duration = current_time - self._state_info.entered_at
            
            return {
                'current_state': self._current_state.name,
                'current_duration': current_duration,
                'previous_state': self._state_info.previous_state.name if self._state_info.previous_state else None,
                'total_transitions': sum(self._transition_count.values()),
                'transition_counts': dict(self._transition_count),
                'state_history_length': len(self._state_history),
                'average_state_durations': {
                    state.name: sum(durations) / len(durations) if durations else 0
                    for state, durations in self._state_durations.items()
                }
            }
    
    def reset(self):
        """Reset state machine to initial state."""
        with self._lock:
            self.logger.info("Resetting state machine")
            
            old_state = self._current_state
            self._transition_to_state(AgentState.INITIALIZING, AgentEvent.RESET_REQUEST)
            
            # Clear event queue
            self._event_queue.clear()
            self._processing_events = False
    
    def _setup_transitions(self):
        """Setup valid state transitions."""
        transitions = [
            # From INITIALIZING
            StateTransition(AgentState.INITIALIZING, AgentEvent.START, AgentState.IDLE),
            
            # From IDLE
            StateTransition(AgentState.IDLE, AgentEvent.SERIAL_CONNECT_REQUEST, AgentState.CONNECTING_SERIAL),
            StateTransition(AgentState.IDLE, AgentEvent.NETWORK_CONNECT_REQUEST, AgentState.CONNECTING_NETWORK),
            StateTransition(AgentState.IDLE, AgentEvent.ERROR_OCCURRED, AgentState.ERROR),
            StateTransition(AgentState.IDLE, AgentEvent.SHUTDOWN_REQUEST, AgentState.SHUTTING_DOWN),
            
            # From CONNECTING_SERIAL
            StateTransition(AgentState.CONNECTING_SERIAL, AgentEvent.SERIAL_CONNECTED, AgentState.SERIAL_CONNECTED),
            StateTransition(AgentState.CONNECTING_SERIAL, AgentEvent.SERIAL_ERROR, AgentState.ERROR),
            StateTransition(AgentState.CONNECTING_SERIAL, AgentEvent.SHUTDOWN_REQUEST, AgentState.SHUTTING_DOWN),
            
            # From SERIAL_CONNECTED
            StateTransition(AgentState.SERIAL_CONNECTED, AgentEvent.NETWORK_CONNECT_REQUEST, AgentState.CONNECTING_NETWORK),
            StateTransition(AgentState.SERIAL_CONNECTED, AgentEvent.SERIAL_DISCONNECTED, AgentState.IDLE),
            StateTransition(AgentState.SERIAL_CONNECTED, AgentEvent.SERIAL_ERROR, AgentState.ERROR),
            StateTransition(AgentState.SERIAL_CONNECTED, AgentEvent.DATA_RECEIVED, AgentState.TRANSMITTING),
            StateTransition(AgentState.SERIAL_CONNECTED, AgentEvent.SHUTDOWN_REQUEST, AgentState.SHUTTING_DOWN),
            
            # From CONNECTING_NETWORK
            StateTransition(AgentState.CONNECTING_NETWORK, AgentEvent.NETWORK_CONNECTED, AgentState.NETWORK_CONNECTED),
            StateTransition(AgentState.CONNECTING_NETWORK, AgentEvent.NETWORK_ERROR, AgentState.ERROR),
            StateTransition(AgentState.CONNECTING_NETWORK, AgentEvent.SHUTDOWN_REQUEST, AgentState.SHUTTING_DOWN),
            
            # From NETWORK_CONNECTED
            StateTransition(AgentState.NETWORK_CONNECTED, AgentEvent.SERIAL_CONNECT_REQUEST, AgentState.CONNECTING_SERIAL),
            StateTransition(AgentState.NETWORK_CONNECTED, AgentEvent.SERIAL_CONNECTED, AgentState.FULLY_CONNECTED),
            StateTransition(AgentState.NETWORK_CONNECTED, AgentEvent.NETWORK_DISCONNECTED, AgentState.IDLE),
            StateTransition(AgentState.NETWORK_CONNECTED, AgentEvent.NETWORK_ERROR, AgentState.ERROR),
            StateTransition(AgentState.NETWORK_CONNECTED, AgentEvent.SHUTDOWN_REQUEST, AgentState.SHUTTING_DOWN),
            
            # From FULLY_CONNECTED
            StateTransition(AgentState.FULLY_CONNECTED, AgentEvent.DATA_RECEIVED, AgentState.TRANSMITTING),
            StateTransition(AgentState.FULLY_CONNECTED, AgentEvent.SERIAL_DISCONNECTED, AgentState.NETWORK_CONNECTED),
            StateTransition(AgentState.FULLY_CONNECTED, AgentEvent.NETWORK_DISCONNECTED, AgentState.SERIAL_CONNECTED),
            StateTransition(AgentState.FULLY_CONNECTED, AgentEvent.SERIAL_ERROR, AgentState.ERROR),
            StateTransition(AgentState.FULLY_CONNECTED, AgentEvent.NETWORK_ERROR, AgentState.ERROR),
            StateTransition(AgentState.FULLY_CONNECTED, AgentEvent.SHUTDOWN_REQUEST, AgentState.SHUTTING_DOWN),
            
            # From TRANSMITTING
            StateTransition(AgentState.TRANSMITTING, AgentEvent.TRANSMISSION_COMPLETE, AgentState.FULLY_CONNECTED),
            StateTransition(AgentState.TRANSMITTING, AgentEvent.DATA_RECEIVED, AgentState.TRANSMITTING),  # Stay in transmitting
            StateTransition(AgentState.TRANSMITTING, AgentEvent.SERIAL_DISCONNECTED, AgentState.NETWORK_CONNECTED),
            StateTransition(AgentState.TRANSMITTING, AgentEvent.NETWORK_DISCONNECTED, AgentState.SERIAL_CONNECTED),
            StateTransition(AgentState.TRANSMITTING, AgentEvent.SERIAL_ERROR, AgentState.ERROR),
            StateTransition(AgentState.TRANSMITTING, AgentEvent.NETWORK_ERROR, AgentState.ERROR),
            StateTransition(AgentState.TRANSMITTING, AgentEvent.SHUTDOWN_REQUEST, AgentState.SHUTTING_DOWN),
            
            # From ERROR
            StateTransition(AgentState.ERROR, AgentEvent.RECONNECT_REQUEST, AgentState.RECONNECTING),
            StateTransition(AgentState.ERROR, AgentEvent.RESET_REQUEST, AgentState.INITIALIZING),
            StateTransition(AgentState.ERROR, AgentEvent.SHUTDOWN_REQUEST, AgentState.SHUTTING_DOWN),
            
            # From RECONNECTING
            StateTransition(AgentState.RECONNECTING, AgentEvent.RECONNECT_SUCCESS, AgentState.IDLE),
            StateTransition(AgentState.RECONNECTING, AgentEvent.RECONNECT_FAILED, AgentState.ERROR),
            StateTransition(AgentState.RECONNECTING, AgentEvent.SHUTDOWN_REQUEST, AgentState.SHUTTING_DOWN),
            
            # From SHUTTING_DOWN
            StateTransition(AgentState.SHUTTING_DOWN, AgentEvent.SHUTDOWN_REQUEST, AgentState.SHUTDOWN),
            
            # Global transitions
            StateTransition(AgentState.INITIALIZING, AgentEvent.SHUTDOWN_REQUEST, AgentState.SHUTTING_DOWN),
        ]
        
        for transition in transitions:
            key = (transition.from_state, transition.event)
            self._transitions[key] = transition
    
    def _setup_state_handlers(self):
        """Setup handlers for each state."""
        self._state_handlers = {
            AgentState.INITIALIZING: self._handle_initializing,
            AgentState.IDLE: self._handle_idle,
            AgentState.CONNECTING_SERIAL: self._handle_connecting_serial,
            AgentState.SERIAL_CONNECTED: self._handle_serial_connected,
            AgentState.CONNECTING_NETWORK: self._handle_connecting_network,
            AgentState.NETWORK_CONNECTED: self._handle_network_connected,
            AgentState.FULLY_CONNECTED: self._handle_fully_connected,
            AgentState.TRANSMITTING: self._handle_transmitting,
            AgentState.ERROR: self._handle_error,
            AgentState.RECONNECTING: self._handle_reconnecting,
            AgentState.SHUTTING_DOWN: self._handle_shutting_down,
            AgentState.SHUTDOWN: self._handle_shutdown,
        }
    
    def _process_event_queue(self):
        """Process queued events."""
        self._processing_events = True
        
        try:
            while self._event_queue:
                event, metadata = self._event_queue.pop(0)
                self._process_event(event, metadata)
        finally:
            self._processing_events = False
    
    def _process_event(self, event: AgentEvent, metadata: Dict[str, Any]):
        """Process a single event."""
        transition_key = (self._current_state, event)
        
        if transition_key not in self._transitions:
            self.logger.warning(f"No transition defined for {self._current_state.name} + {event.name}")
            return
        
        transition = self._transitions[transition_key]
        
        # Check condition if present
        if transition.condition and not transition.condition():
            self.logger.debug(f"Transition condition failed for {self._current_state.name} + {event.name}")
            return
        
        # Execute action if present
        if transition.action:
            try:
                transition.action()
            except Exception as e:
                self.logger.error(f"Error executing transition action: {e}")
                return
        
        # Perform transition
        old_state = self._current_state
        self._transition_to_state(transition.to_state, event, metadata)
        
        # Notify transition callback
        if self.transition_callback:
            try:
                self.transition_callback(old_state, event, transition.to_state)
            except Exception as e:
                self.logger.error(f"Error in transition callback: {e}")
    
    def _transition_to_state(self, new_state: AgentState, event: AgentEvent, metadata: Optional[Dict[str, Any]] = None):
        """Transition to a new state."""
        old_state = self._current_state
        current_time = time.time()
        
        # Record state duration
        duration = current_time - self._state_info.entered_at
        self._state_durations[old_state].append(duration)
        
        # Update state info
        self._current_state = new_state
        self._state_info = StateInfo(
            state=new_state,
            entered_at=current_time,
            previous_state=old_state,
            metadata=metadata or {}
        )
        
        # Record in history
        self._state_history.append({
            'from_state': old_state.name,
            'to_state': new_state.name,
            'event': event.name,
            'timestamp': current_time,
            'duration_in_previous_state': duration
        })
        
        # Update statistics
        self._transition_count[f"{old_state.name}->{new_state.name}"] += 1
        
        self.logger.info(f"State transition: {old_state.name} -> {new_state.name} (event: {event.name})")
        
        # Call state handler
        if new_state in self._state_handlers:
            try:
                self._state_handlers[new_state](self._state_info)
            except Exception as e:
                self.logger.error(f"Error in state handler for {new_state.name}: {e}")
        
        # Notify state callback
        if self.state_callback:
            try:
                self.state_callback(self._state_info)
            except Exception as e:
                self.logger.error(f"Error in state callback: {e}")
    
    # State handlers
    def _handle_initializing(self, state_info: StateInfo):
        """Handle INITIALIZING state."""
        self.logger.debug("Agent initializing...")
    
    def _handle_idle(self, state_info: StateInfo):
        """Handle IDLE state."""
        self.logger.debug("Agent is idle")
    
    def _handle_connecting_serial(self, state_info: StateInfo):
        """Handle CONNECTING_SERIAL state."""
        self.logger.debug("Connecting to serial port...")
    
    def _handle_serial_connected(self, state_info: StateInfo):
        """Handle SERIAL_CONNECTED state."""
        self.logger.debug("Serial port connected")
    
    def _handle_connecting_network(self, state_info: StateInfo):
        """Handle CONNECTING_NETWORK state."""
        self.logger.debug("Connecting to network...")
    
    def _handle_network_connected(self, state_info: StateInfo):
        """Handle NETWORK_CONNECTED state."""
        self.logger.debug("Network connected")
    
    def _handle_fully_connected(self, state_info: StateInfo):
        """Handle FULLY_CONNECTED state."""
        self.logger.debug("Fully connected - ready for data transmission")
    
    def _handle_transmitting(self, state_info: StateInfo):
        """Handle TRANSMITTING state."""
        self.logger.debug("Transmitting data...")
    
    def _handle_error(self, state_info: StateInfo):
        """Handle ERROR state."""
        self.logger.warning("Agent in error state")
    
    def _handle_reconnecting(self, state_info: StateInfo):
        """Handle RECONNECTING state."""
        self.logger.debug("Attempting to reconnect...")
    
    def _handle_shutting_down(self, state_info: StateInfo):
        """Handle SHUTTING_DOWN state."""
        self.logger.debug("Agent shutting down...")
    
    def _handle_shutdown(self, state_info: StateInfo):
        """Handle SHUTDOWN state."""
        self.logger.debug("Agent shutdown complete")